/**
 * did:web 解決のキャッシュ層。
 *
 * did:web の解決には次のキャッシュ規則を適用する:
 * - HTTP `Cache-Control: max-age` を尊重し、TTL 上限 600 秒でキャップする。
 * - negative cache（404 / DNS 失敗）は 30 秒固定。
 * - did:key / did:jwk はキャッシュ不要（解決が決定的で I/O が無い）。
 *
 * キャッシュ本体は対象非依存の `internal/cache/ttl-cache.ts` に置き、本モジュールは
 * did:web 固有の判断（キーの取り方・どのエラーを negative cache するか・観測イベント）だけを持つ。
 *
 * セキュリティ上の注意:
 * - キャッシュキーは DID 文字列であり、ログ・例外メッセージ・`context` には載せない。観測イベントに渡すのはメソッド名と状態ラベルのみ。
 */

import {
  type CacheState,
  createTtlCache,
  parseMaxAgeSeconds,
  resolveMaxTtlSeconds,
  systemNowSeconds,
  type TtlCache,
} from '../../cache/index.js';
import { ErrorCodes, VericertsError } from '../../errors.js';
import { ownProperty } from '../../prototype-safety/own-property.js';
import type { DIDDocument } from '../did.js';
import { consumeResolutionBody, type ResolutionWorkBudget } from '../resolution-budget.js';

/**
 * did:web の DID Document キャッシュ TTL 上限（秒）。
 *
 * 上限 600 秒。Subordinate Statement の `revoked_keys` で鍵の失効を宣言した後に、
 * 古い鍵を含む DID Document がキャッシュに残る時間を制限する。
 *
 * 同じ SLA から導かれる値が Federation 側にもある:
 * `internal/trust/federation/revocation/key-revocation.ts` の `KEY_REVOCATION_PROPAGATION_MAX_SECONDS`（600）。
 * 数値が一致するのは偶然ではなく同一 SLA だからだが、identity ドメインが trust ドメインの定数を
 * import すると「did:web の TTL が Federation の実装都合で動く」という依存が生まれるため、
 * 値は複製し、根拠の同一性はこのコメントで結ぶ（片方を変えるときは必ず両方を見ること）。
 */
export const DID_WEB_CACHE_MAX_TTL_SECONDS = 600;

/**
 * キャッシュに格納する DID Document 1 件の本文長の上限（文字数）。
 *
 * 取得上限（`MAX_DOCUMENT_BYTES` = 1 MiB）の本文は `JSON.parse` 後に 26 倍程度のヒープになり得る。
 * 攻撃者が署名検証前の `iss` に相異なる did:web を並べるだけで数 GB を保持させられるため、
 * 実用的な文書（数 KB）より十分大きい 64 KiB を超える文書はキャッシュしない（解決自体は成功させる）。
 */
export const DID_WEB_CACHE_MAX_ENTRY_LENGTH = 64 * 1024;

/** キャッシュ全体が保持する本文長の合計上限（文字数）。超過分は古い順に捨てる。 */
export const DID_WEB_CACHE_MAX_TOTAL_LENGTH = 2 * 1024 * 1024;

/**
 * キャッシュした DID Document → 取得時の本文長（文字数）。キャッシュヒットした文書もスコープの間は保持されるため、
 * 解決スコープの本文量予算へ同じ長さを計上するのに使う。`TtlCache.get` は重みを返さないので別に持つ。
 * 文書が GC されれば項目も消えるので、キャッシュの寿命とは独立に漏れない。
 */
const cachedBodyLength = new WeakMap<DIDDocument, number>();

/** キャッシュ観測イベント（`method` / `cache` ラベル）。 */
export interface DidWebCacheEvent {
  /** DID メソッド名（did:web では常に `'web'`）。 */
  readonly method: string;
  /** キャッシュ状態（`cold` / `warm` / `hot`）。`did.cache_hit` は `hot` のときに限り true。 */
  readonly state: CacheState;
}

/** `resolveDidWeb` / `MethodWeb` に注入する依存（すべて任意。未指定なら既定動作）。 */
export interface ResolveDidWebDeps {
  /** HTTP 取得関数。未指定ならグローバル `fetch`（テストでの決定性のために注入する）。 */
  readonly fetchFn?: typeof fetch;
  /** 現在時刻（エポック秒）。未指定なら実時計。 */
  readonly nowSeconds?: () => number;
  /** DID Document キャッシュ。未指定ならキャッシュしない（`resolveDidWeb` は状態を持たない）。 */
  readonly cache?: TtlCache<DIDDocument>;
  /** TTL 上限（秒）。`DID_WEB_CACHE_MAX_TTL_SECONDS` 以下のみ許可（緩和は拒否）。 */
  readonly maxTtlSeconds?: number;
  /** キャッシュ状態の観測フック（メトリクス / span 属性の記録点）。 */
  readonly onCacheEvent?: (event: DidWebCacheEvent) => void;
}

/** キャッシュ層に渡す取得結果（DID Document と、TTL 決定に使う `Cache-Control`）。 */
export interface DidWebFetchResult {
  /** 検証済み DID Document。 */
  readonly document: DIDDocument;
  /** レスポンスの `Cache-Control` ヘッダ値（未設定なら null）。 */
  readonly cacheControl: string | null;
  /** 取得した本文の長さ（文字数）。キャッシュの保持量（重み）に使う。 */
  readonly bodyLength: number;
}

/** 観測フックへ状態を通知する（フック未設定なら何もしない）。 */
function emitCacheEvent(deps: ResolveDidWebDeps, state: CacheState): void {
  ownProperty<ResolveDidWebDeps['onCacheEvent']>(deps, 'onCacheEvent')?.({ method: 'web', state });
}

/**
 * did:web 用の DID Document キャッシュを生成する。
 *
 * TTL 上限は `DID_WEB_CACHE_MAX_TTL_SECONDS`（600 秒）で固定する。ここを緩める設定は
 * `resolveMaxTtlSeconds` が拒否するため、生成側では受け付けない。
 *
 * @param nowSeconds 時計（エポック秒）。未指定なら実時計。
 * @param maxEntries 保持する最大エントリ数（省略時はキャッシュ層の既定）。
 * @returns did:web 用 TTL キャッシュ。
 */
export function createDidWebCache(
  nowSeconds: () => number = systemNowSeconds,
  maxEntries?: number,
): TtlCache<DIDDocument> {
  const budget = { maxTotalWeight: DID_WEB_CACHE_MAX_TOTAL_LENGTH };
  return createTtlCache<DIDDocument>(
    maxEntries === undefined
      ? { maxTtlSeconds: DID_WEB_CACHE_MAX_TTL_SECONDS, nowSeconds, ...budget }
      : { maxTtlSeconds: DID_WEB_CACHE_MAX_TTL_SECONDS, nowSeconds, maxEntries, ...budget },
  );
}

/**
 * DID Document も取得失敗も一切記憶しない did:web 用キャッシュ（キャッシュなし）。`MethodWeb` は `cache` 省略時に TTL キャッシュ
 * （`Cache-Control` に従って最長 600 秒、取得失敗は 30 秒）を持つので、署名のたびに最新の `did.json` で鍵を照合する経路
 * （取り込んだ DID のペルソナ署名・取り込み）は `new MethodWeb({ cache: NO_DID_WEB_CACHE })` で毎回取得させる。
 * 状態を持たないので共有してよい。
 */
export const NO_DID_WEB_CACHE: TtlCache<DIDDocument> = {
  get: () => undefined,
  set: () => undefined,
  setNegative: () => undefined,
  getNegative: () => undefined,
  delete: () => undefined,
  clear: () => undefined,
  size: 0,
};

/**
 * 取得失敗を negative cache に記憶してよいエラーかを判定する。
 *
 * 記憶するのは `DID_NOT_FOUND`（2003）だけ。2003 は 404 / ネットワーク・DNS 失敗 /
 * タイムアウト / 非 HTTPS リダイレクトを束ねたコードで、「取得先が今は応答しない」という
 * 短時間持続しやすい状態を表すため、30 秒の記憶が再取得の濫発を抑える。
 *
 * 除外するもの:
 * - `DID_DOC_INVALID`（2010）: 取得自体は成功しており、内容が不正なだけ。配信側の差し替えで
 *   すぐ直り得るうえ、`doc.id` 不一致のような検証失敗を 30 秒記憶しても得が無い。
 * - `INVALID_DID`（2001）: DID 文字列の構文不正で、そもそもネットワークに到達しない
 *   （`didWebToUrl` が変換段階で弾く）。記憶する対象が存在しない。
 *
 * @param error 捕捉した例外。
 * @returns negative cache に記憶すべきなら `true`。
 */
function isNegativeCacheable(error: unknown): boolean {
  return error instanceof VericertsError && error.code === ErrorCodes.DID_NOT_FOUND;
}

/**
 * did:web の DID Document をキャッシュ経由で解決する。
 *
 * 状態遷移（`cache` ラベル）:
 * - エントリ無し → `cold`（ネットワーク取得）
 * - エントリ有り・TTL 切れ → `warm`（再取得。staleness の観測点）
 * - エントリ有り・TTL 内 → `hot`（ネットワーク I/O 無し）
 *
 * 採用 TTL は `min(Cache-Control の max-age ?? 上限, 上限)`。**配信側が返す過大な `max-age` は
 * キャップする**（解決を失敗させない）のに対し、**SDK 利用者が `deps.maxTtlSeconds` で上限を
 * 緩めようとした場合は拒否する**（`resolveMaxTtlSeconds`）。前者は制御できない他者の設定、
 * 後者は制御できる自分の設定であり、扱いを分ける。
 *
 * 記憶済みの取得失敗（negative cache）がある間はネットワークに出ず、同じエラーを再送出する。
 * この経路もネットワーク I/O が無いため `hot` として観測する。
 *
 * @param key キャッシュキー（DID 文字列）。
 * @param deps 注入する依存（キャッシュ・時計・TTL 上限・観測フック）。
 * @param fetchDocument 実際に取得を行う関数（キャッシュミス時のみ呼ばれる）。
 * @param scope 解決スコープの予算。キャッシュヒットした文書もスコープに保持されるため、取得時の本文長を
 *   本文量として計上する（取得した場合の計上は `fetchDocument` 側）。
 * @returns DID Document。
 * @throws TTL 上限設定が不正な場合（VericertsError、code `3002`）、
 *         および `fetchDocument` が投げた例外をそのまま。
 */
export async function resolveWithDidWebCache(
  key: string,
  deps: ResolveDidWebDeps,
  fetchDocument: () => Promise<DidWebFetchResult>,
  scope?: ResolutionWorkBudget,
): Promise<DIDDocument> {
  // 利用者設定の検証はキャッシュの有無に依らず先に行う（設定ミスを黙って通さない）。
  const maxTtlSeconds = resolveMaxTtlSeconds(
    ownProperty<number>(deps, 'maxTtlSeconds'),
    DID_WEB_CACHE_MAX_TTL_SECONDS,
  );
  const cache = ownProperty<TtlCache<DIDDocument>>(deps, 'cache');
  if (cache === undefined) {
    // キャッシュ未注入時は毎回取得する（従来どおりの状態を持たない解決）。
    emitCacheEvent(deps, 'cold');
    return (await fetchDocument()).document;
  }

  const now = (ownProperty<() => number>(deps, 'nowSeconds') ?? systemNowSeconds)();
  const remembered = cache.getNegative(key, now);
  if (remembered !== undefined) {
    emitCacheEvent(deps, 'hot');
    throw remembered;
  }
  const entry = cache.get(key, now);
  if (entry !== undefined && !entry.expired) {
    // 長さが不明（外部注入キャッシュに事前投入された文書）なら格納可能な最大長で見積もる（fail-closed）。
    consumeResolutionBody(
      scope,
      cachedBodyLength.get(entry.value) ?? DID_WEB_CACHE_MAX_ENTRY_LENGTH,
    );
    emitCacheEvent(deps, 'hot');
    return entry.value;
  }
  emitCacheEvent(deps, entry === undefined ? 'cold' : 'warm');

  try {
    const fetched = await fetchDocument();
    // 配信側の max-age は上限でキャップする。未指定なら上限をそのまま採用する。
    const ttlSeconds =
      fetched.bodyLength > DID_WEB_CACHE_MAX_ENTRY_LENGTH
        ? 0
        : Math.min(parseMaxAgeSeconds(fetched.cacheControl) ?? maxTtlSeconds, maxTtlSeconds);
    // 成功の格納は同キーの negative エントリも消す（TTL 0 で格納しない場合も同じ）。
    // 重みは取得本文の長さ。JSON.parse 後のヒープは本文の数十倍になり得るため件数だけでは不足。
    cache.set(key, fetched.document, ttlSeconds, now, fetched.bodyLength);
    cachedBodyLength.set(fetched.document, fetched.bodyLength);
    return fetched.document;
  } catch (error) {
    if (isNegativeCacheable(error)) {
      cache.setNegative(key, error, now);
    }
    throw error;
  }
}
