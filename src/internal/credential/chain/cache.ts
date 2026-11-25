/**
 * Credential Chain 検証結果の TTL キャッシュ。
 *
 * VC チェーン検証（深さ 10）は < 1 秒、キャッシュヒット時 < 200ms が要件。本キャッシュは
 * 呼び出し側が組み立てたキーで検証結果を既定で 5 分保持し、親 VC 失効通知（`invalidateChain`）でバスト無効化する。
 *
 * キーは起点 VC ID **だけではない**。結果を左右する検証オプション（`policy` / `maxDepth` /
 * `customHandler`）を含める責務は呼び出し側（`verify.ts` の `cacheKeyFor`）にある。起点 ID だけを
 * キーにすると `policy: "permissive"` の結果が後続の `policy: "strict"` にヒットする fail-open になる。
 */

import { DEFAULT_CACHE_MAX_ENTRIES } from '../../cache/ttl-cache.js';
import { ownProperty } from '../../prototype-safety/own-property.js';
import type { ChainVerificationResult } from './types.js';
import { CHAIN_CACHE_TTL_MS } from './types.js';

/** キャッシュエントリ（検証結果 + 記録時刻 + 保持量の見積り）。 */
interface CacheEntry {
  readonly result: ChainVerificationResult;
  readonly storedAt: number;
  readonly weight: number;
}

/**
 * `invalidated` 記録の保持期間を `ttlMs`（キャッシュ本体の TTL）の何倍にするか。
 *
 * `entries` は `ttlMs` で自然に空になるため、失効通知から `ttlMs` の数倍以上が経過した後は、
 * その VC ID を含む古いキャッシュエントリはもう存在し得ない。それ以降も `invalidated` に
 * 記録し続けることにキャッシュ上のメリットは無くメモリコストだけが残るため、この倍率を
 * 超えた記録は掃除する。
 */
const INVALIDATED_RETENTION_MULTIPLIER = 3;

/** 全エントリの重みの合計上限。`UrlKeyedTtlCache` の `URL_CACHE_MAX_TOTAL_WEIGHT` と同値。 */
export const CHAIN_CACHE_MAX_TOTAL_WEIGHT = 2 * 1024 * 1024;

/** 結果オブジェクト・ノード 1 件・配列の固定オーバーヘッドの見積り（文字列長に加算する）。 */
const NODE_OVERHEAD = 64;

/**
 * エントリの保持量を見積もる（キー + 起点 ID + 各ノードの ID + 警告文字列）。
 *
 * `vcId` は攻撃者が選べる任意長の文字列で、1 呼び出しあたり入力の数十倍を保持する（70 バイトの ID で約
 * 4.2 KB）。件数だけで縛ると 1 件ごとの大きさが効かないので、文字列長を重みに含めて総量でも縛る。
 */
function weightOf(key: string, result: ChainVerificationResult): number {
  let weight = key.length + result.vcId.length + NODE_OVERHEAD;
  for (const node of result.chain) {
    weight += node.vcId.length + NODE_OVERHEAD;
  }
  for (const warning of ownProperty<readonly string[]>(result, 'warnings') ?? []) {
    weight += warning.length + NODE_OVERHEAD;
  }
  return weight + (ownProperty<string>(result, 'reason')?.length ?? 0);
}

/**
 * VC チェーン検証結果の TTL キャッシュ。
 *
 * キーは呼び出し側が組み立てた文字列（起点 VC ID + 結果を左右するオプション）。`get` は TTL（既定 5 分）内かつ、キャッシュ結果に含まれるどのノード ID も
 * `invalidateChain` で無効化されていない場合のみヒットする。親 VC 失効通知を受けたら
 * `invalidateChain`（親 ID）を呼ぶと、その親を含むチェーンのキャッシュがバストされ、以降その ID を
 * 含むチェーンは再ヒットしなくなる（失効は非可逆のため恒久バストで安全側に倒す）。
 *
 * **保持量は件数・総量の両方で縛る**。キー（`vcId`）は攻撃者が選べるので、相異なる `vcId` の検証を
 * 繰り返されると、TTL 切れでも「同じキーを `get` したとき」にしか消えない旧実装では `entries` が単調に増え
 * （26 万件で約 1.09 GB）、長寿命プロセス / Service Worker が OOM になった。そこで (1) `maxEntries` と
 * 重みの合計 `maxTotalWeight` を超えたら最近使っていない順に追い出し（`get` のヒットで最新に更新する LRU）、
 * (2) `set` のたびに TTL 切れの全エントリを掃引する。追い出しても再検証されるだけで、判定が緩む経路は無い。
 *
 * `invalidated` の各記録は無効化時刻を持ち、`ttlMs` の `INVALIDATED_RETENTION_MULTIPLIER` 倍を
 * 超えて古くなった記録は `get` / `invalidateChain` の呼び出し時に掃除する（無制限に
 * 増え続けるメモリリークの防止）。掃除しても安全性は変わらない。その時点で `entries` 側は TTL で
 * とうに空になっているため、掃除された ID を含む新規エントリが `set` されるとすれば、それは
 * 掃除後に行われた新しい検証（＝現在の失効状態を反映済み）の結果である。
 *
 * @experimental 公開直後は挙動・シグネチャが変わり得る（v1.0 で `@stable` 昇格予定）。
 */
export class ChainVerificationCache {
  /** 挿入順 = 最近使った順（`get` のヒットで末尾へ移す）。先頭が追い出し候補。 */
  private readonly entries = new Map<string, CacheEntry>();
  /** 明示的に無効化された VC ID → 無効化を記録した時刻（親失効伝搬のバスト対象）。 */
  private readonly invalidated = new Map<string, number>();
  private readonly ttlMs: number;
  private readonly maxEntries: number;
  private readonly maxTotalWeight: number;
  /** 保持中エントリの重みの合計（`maxTotalWeight` の判定用）。 */
  private totalWeight = 0;

  /**
   * @param ttlMs キャッシュ TTL（ミリ秒、既定 5 分）。
   * @param maxEntries 保持する最大エントリ数（既定 `DEFAULT_CACHE_MAX_ENTRIES`）。
   * @param maxTotalWeight 重みの合計上限（既定 {@link CHAIN_CACHE_MAX_TOTAL_WEIGHT}）。
   */
  constructor(
    ttlMs: number = CHAIN_CACHE_TTL_MS,
    maxEntries: number = DEFAULT_CACHE_MAX_ENTRIES,
    maxTotalWeight: number = CHAIN_CACHE_MAX_TOTAL_WEIGHT,
  ) {
    this.ttlMs = ttlMs;
    this.maxEntries = maxEntries;
    this.maxTotalWeight = maxTotalWeight;
  }

  /** 保持中のエントリ数（テスト / 診断用）。 */
  get size(): number {
    return this.entries.size;
  }

  /**
   * 起点 ID のキャッシュ結果を取得する。TTL 切れ・無効化済みノードを含む場合は `undefined`。
   *
   * @param key 呼び出し側が組み立てたキャッシュキー（起点 VC ID + 結果を左右するオプション）。
   * @param now 現在時刻（エポックミリ秒）。
   */
  get(key: string, now: number): ChainVerificationResult | undefined {
    this.pruneInvalidated(now);
    const entry = this.entries.get(key);
    if (entry === undefined) {
      return undefined;
    }
    // `now` が NaN なら `>=` は常に false、-Infinity なら差が -Infinity になり、TTL 切れエントリを返し続ける。
    // 有限な時刻でなければ miss として扱う（fail-closed）。
    if (!Number.isFinite(now) || now - entry.storedAt >= this.ttlMs) {
      // TTL 切れ。エントリを破棄して miss を返す。
      this.remove(key);
      return undefined;
    }
    // チェーン内のいずれかのノードが無効化されていればバスト（親失効伝搬）。
    for (const node of entry.result.chain) {
      if (this.invalidated.has(node.vcId)) {
        this.remove(key);
        return undefined;
      }
    }
    // LRU: ヒットしたエントリを最新側へ移す。
    this.entries.delete(key);
    this.entries.set(key, entry);
    return entry.result;
  }

  /**
   * 起点 ID のキャッシュ結果を保存する。
   *
   * TTL 切れの全エントリを掃引してから挿入し、件数 / 総量の上限を超えた分は最近使っていない順に
   * 追い出す。単独で総量上限を超える結果は保存しない。`now` が有限でなければ保存しない
   * （`storedAt` が NaN だと TTL 判定が常に偽になり、永久に残る）。
   *
   * @param key 呼び出し側が組み立てたキャッシュキー（起点 VC ID + 結果を左右するオプション）。
   * @param result チェーン検証結果。
   * @param now 現在時刻（エポックミリ秒）。
   */
  set(key: string, result: ChainVerificationResult, now: number): void {
    if (!Number.isFinite(now)) {
      return;
    }
    this.pruneExpired(now);
    this.remove(key);
    const weight = weightOf(key, result);
    if (weight > this.maxTotalWeight) {
      return;
    }
    this.entries.set(key, { result, storedAt: now, weight });
    this.totalWeight += weight;
    while (this.entries.size > this.maxEntries || this.totalWeight > this.maxTotalWeight) {
      const oldest = this.entries.keys().next();
      if (oldest.done === true) {
        break;
      }
      this.remove(oldest.value);
    }
  }

  /**
   * 指定 VC（多くは失効した親）を含むチェーンのキャッシュをバスト無効化する。
   *
   * 以降その ID をノードに含むキャッシュはヒットしなくなる。子 VC の再検証時に失効伝搬が反映される。
   *
   * @param credentialId 失効した VC の ID（親 / 任意のノード）。
   * @param now 現在時刻（エポックミリ秒、無効化記録の保持期間判定に使う）。
   */
  invalidateChain(credentialId: string, now: number): void {
    this.pruneInvalidated(now);
    this.invalidated.set(credentialId, now);
    // 既存エントリのうち当該 ID を含むものは即時削除する（メモリと再ヒットの両方を防ぐ）。
    for (const [entryKey, entry] of [...this.entries]) {
      if (entry.result.chain.some((n) => n.vcId === credentialId)) {
        this.remove(entryKey);
      }
    }
  }

  /** エントリを 1 件削除し、重みの合計から差し引く。 */
  private remove(key: string): void {
    const entry = this.entries.get(key);
    if (entry !== undefined) {
      this.totalWeight -= entry.weight;
      this.entries.delete(key);
    }
  }

  /** TTL を過ぎたエントリをすべて掃引する（`set` のたびに実行。保持数は `maxEntries` で有界）。 */
  private pruneExpired(now: number): void {
    for (const [key, entry] of [...this.entries]) {
      if (now - entry.storedAt >= this.ttlMs) {
        this.remove(key);
      }
    }
  }

  /**
   * 保持期間（`ttlMs` の `INVALIDATED_RETENTION_MULTIPLIER` 倍）を超えた `invalidated` 記録を掃除する。
   *
   * `get` / `invalidateChain` の呼び出しごとに実行し、プロセス生存期間中の単調増加を防ぐ。
   */
  private pruneInvalidated(now: number): void {
    const retentionMs = this.ttlMs * INVALIDATED_RETENTION_MULTIPLIER;
    for (const [vcId, recordedAt] of this.invalidated) {
      if (now - recordedAt >= retentionMs) {
        this.invalidated.delete(vcId);
      }
    }
  }

  /** キャッシュと無効化記録をすべてクリアする（テスト / 再初期化用）。 */
  clear(): void {
    this.entries.clear();
    this.invalidated.clear();
    this.totalWeight = 0;
  }
}
