/**
 * URL をキーにした固定 TTL・FIFO 上限付きのインメモリキャッシュ（共有プリミティブ）。
 *
 * `ttl-cache.ts` の `createTtlCache` とは別物である。あちらは配信側の `Cache-Control` を
 * 尊重して `set` ごとに TTL（秒）を受け取り negative cache も持つが、こちらは
 * **インスタンス生成時に固定した単一の TTL（ミリ秒）**だけを見る単純な形である。
 * 「取得元 URL をキーに文書を一定時間持ち回る」だけの用途で両者を無理に統合すると、
 * 使わない機能（negative cache / ヘッダ解釈）の分だけ呼び出し側の判断が増えるため分けている。
 *
 * 時刻は `now` を引数で受け取り、内部で `Date.now()` を呼ばない（テストの決定性）。
 *
 * 利用者（いずれも**独立したインスタンス**を生成する）:
 * - Type Metadata 経路（`credential/sdjwt/type-metadata/cache.ts`）
 * - W3C `credentialSchema` 経路（`credential/vc/credential-schema/cache.ts`）
 *
 * 両者は別エコシステムであり、キャッシュ状態を共有してはならない。本クラスを共有しても
 * 状態が混ざることはない（実装を共有するだけで、呼び出し側が各々 `new` するため）。
 *
 * セキュリティ上の注意:
 * - キーは URL 文字列そのもの（完全一致）のみとし、VC 由来の値を連結した複合キーは作らない。
 * - エントリ数に上限を設ける。URL は Issuer が自由に決められるため、毎回異なる URL の
 *   クレデンシャルを流されるとエントリが際限なく積み上がる（1 エントリ最大 1 MiB）。
 *   上限超過時は挿入順に古いものから捨てる（FIFO）。キャッシュはあくまで往復削減の最適化で、
 *   追い出しても再取得されるだけなので、追い出しによって判定が緩む経路は無い。
 * - キーはログ出力せず、例外メッセージにも含めない。
 */

import { DEFAULT_CACHE_MAX_ENTRIES } from './ttl-cache.js';

/**
 * 1 件が保持を許される重み（`JSON.stringify` 後の文字数）の上限。取得上限（1 MiB）の本文は `JSON.parse`
 * 後に 26 倍程度のヒープになり得る。実用的なスキーマ / Type Metadata（数 KB）より十分大きい 64 KiB を超える文書は
 * キャッシュしない（取得・検証自体は成功させる）。`did-web-cache.ts` の `DID_WEB_CACHE_MAX_ENTRY_LENGTH` と同値。
 */
export const URL_CACHE_MAX_ENTRY_WEIGHT = 64 * 1024;

/** 全エントリの重みの合計上限。超過分は古い順に捨てる。`DID_WEB_CACHE_MAX_TOTAL_LENGTH` と同値。 */
export const URL_CACHE_MAX_TOTAL_WEIGHT = 2 * 1024 * 1024;

/** キャッシュエントリ（取得済み文書 + 記録時刻 + 重み）。 */
interface CacheEntry<T> {
  readonly value: T;
  readonly storedAt: number;
  readonly weight: number;
}

/**
 * 値の重み（`JSON.stringify` 後の文字数）。JSON にできない値（循環参照・BigInt 等）は `Infinity`
 * （= 格納しない、fail-closed）。`undefined` / 関数は文字列にならないため 0。
 */
function weightOf(value: unknown): number {
  try {
    return JSON.stringify(value)?.length ?? 0;
  } catch {
    return Number.POSITIVE_INFINITY;
  }
}

/**
 * URL をキーに値を固定 TTL で保持するキャッシュ。
 *
 * 用途ごとの既定 TTL は呼び出し側（サブクラス）が与える。本クラスは既定値を持たない。
 */
export class UrlKeyedTtlCache<T> {
  private readonly entries = new Map<string, CacheEntry<T>>();
  private readonly ttlMs: number;
  private readonly maxEntries: number;
  private readonly maxEntryWeight: number;
  private readonly maxTotalWeight: number;
  /** 保持中エントリの重みの合計（`maxTotalWeight` の判定用）。 */
  private totalWeight = 0;

  /**
   * @param ttlMs キャッシュ TTL（ミリ秒）。既定値は持たず、用途ごとに明示する。
   * @param maxEntries 保持する最大エントリ数（既定 `DEFAULT_CACHE_MAX_ENTRIES`）。
   * @param maxEntryWeight 1 件の重みの上限（既定 {@link URL_CACHE_MAX_ENTRY_WEIGHT}）。
   * @param maxTotalWeight 重みの合計上限（既定 {@link URL_CACHE_MAX_TOTAL_WEIGHT}）。
   */
  constructor(
    ttlMs: number,
    maxEntries: number = DEFAULT_CACHE_MAX_ENTRIES,
    maxEntryWeight: number = URL_CACHE_MAX_ENTRY_WEIGHT,
    maxTotalWeight: number = URL_CACHE_MAX_TOTAL_WEIGHT,
  ) {
    this.ttlMs = ttlMs;
    this.maxEntries = maxEntries;
    this.maxEntryWeight = maxEntryWeight;
    this.maxTotalWeight = maxTotalWeight;
  }

  /**
   * URL に対応する値を取得する。TTL 切れなら `undefined`（エントリは削除する）。
   *
   * 失効判定は境界を含む: `now - storedAt === ttlMs` は失効済みとして扱う。
   *
   * @param url 取得元 URL（完全一致のみをキーとする）。
   * @param now 現在時刻（エポックミリ秒）。
   */
  get(url: string, now: number): T | undefined {
    const entry = this.entries.get(url);
    if (entry === undefined) {
      return undefined;
    }
    // `now` が NaN なら `>=` は常に false、-Infinity なら差が -Infinity になり、TTL 切れエントリを返し続ける。
    // 有限な時刻でなければ miss として扱う（fail-closed）。
    if (!Number.isFinite(now) || now - entry.storedAt >= this.ttlMs) {
      this.remove(url);
      return undefined;
    }
    return entry.value;
  }

  /**
   * URL に対応する値を記録する。
   *
   * エントリ数または重みの合計が上限を超えたら、挿入順に古いものから追い出す（FIFO）。重みが 1 件の上限を超える
   * 値は格納しない（同じ URL の古い値は残さず消す）。
   *
   * @param url 取得元 URL（完全一致のみをキーとする）。
   * @param value 記録する値。
   * @param now 現在時刻（エポックミリ秒）。
   */
  set(url: string, value: T, now: number): void {
    // 挿入順を最新に揃えるため、既存キーはいったん削除してから入れ直す。
    this.remove(url);
    const weight = weightOf(value);
    if (weight > this.maxEntryWeight) {
      return;
    }
    this.entries.set(url, { value, storedAt: now, weight });
    this.totalWeight += weight;
    while (this.entries.size > this.maxEntries || this.totalWeight > this.maxTotalWeight) {
      const oldest = this.entries.keys().next();
      if (oldest.done === true) {
        return;
      }
      this.remove(oldest.value);
    }
  }

  /** キャッシュをすべてクリアする（テスト / 再初期化用）。 */
  clear(): void {
    this.entries.clear();
    this.totalWeight = 0;
  }

  private remove(url: string): void {
    const entry = this.entries.get(url);
    if (entry !== undefined) {
      this.totalWeight -= entry.weight;
      this.entries.delete(url);
    }
  }
}
