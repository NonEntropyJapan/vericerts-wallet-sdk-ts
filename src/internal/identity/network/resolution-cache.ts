/**
 * did:ebsi / did:ion / did:cheqd の解決結果キャッシュ。
 *
 * 3 メソッドの解決結果はノード運営者の応答で、鍵のローテーション・アンカー後の操作の公開などで変わり得る。
 * TTL は **600 秒を上限**とし（提案）、`Cache-Control` は尊重しない（ノードごとの設定ミスで長く保持しない）。
 * キャッシュはメソッドのインスタンスに閉じ、キーは呼び出し側が組み立てる（did:ebsi は `(did, validAt)`）。
 * 失敗は記憶しない（negative cache なし）。取得に使う本文は 1 件 64 KiB 超を格納せず、合計 2 MiB まで。
 */

import { createTtlCache, systemNowSeconds, type TtlCache } from '../../cache/index.js';
import { consumeResolutionBody, type ResolutionWorkBudget } from '../resolution-budget.js';

/** キャッシュ TTL の上限（秒）。 */
export const RESOLUTION_CACHE_TTL_SECONDS = 600;

/** 1 件の格納を許す本文の文字数上限。 */
const MAX_ENTRY_WEIGHT = 64 * 1024;

/** 保持する本文の文字数の合計上限。 */
const MAX_TOTAL_WEIGHT = 2 * 1024 * 1024;

/** 取得結果と、そのキャッシュ上の重み（本文の文字数）。 */
export interface Loaded<T> {
  readonly value: T;
  readonly weight: number;
}

/**
 * `getOrLoad` だけを要求するキャッシュの形。`did:ebsi` / `did:ion` / `did:cheqd` のメソッドは設定でこれを差し替えられる
 * （既定は {@link ResolutionCache}）。署名のたびに最新の DID Document で鍵を照合する経路は {@link NO_RESOLUTION_CACHE} を渡す。
 */
export interface ResolutionCacheLike<T> {
  getOrLoad(key: string, load: () => Promise<Loaded<T>>, scope?: ResolutionWorkBudget): Promise<T>;
}

/**
 * 何も記憶せず、毎回 `load` で取得する {@link ResolutionCacheLike}（キャッシュなし）。状態を持たないので全メソッドで共有する。
 * 取得時の本文量は `load` 側が計上する。
 */
export const NO_RESOLUTION_CACHE: {
  getOrLoad<T>(
    key: string,
    load: () => Promise<Loaded<T>>,
    scope?: ResolutionWorkBudget,
  ): Promise<T>;
} = {
  getOrLoad: async (_key, load) => (await load()).value,
};

/** 解決結果の TTL キャッシュ。 */
export class ResolutionCache<T> implements ResolutionCacheLike<T> {
  private readonly cache: TtlCache<Loaded<T>>;
  private readonly nowSeconds: () => number;

  /** @param nowSeconds 時計（秒。テスト用に差し替える。省略時はシステム時計）。 */
  constructor(nowSeconds: () => number = systemNowSeconds) {
    this.nowSeconds = nowSeconds;
    this.cache = createTtlCache<Loaded<T>>({
      maxTtlSeconds: RESOLUTION_CACHE_TTL_SECONDS,
      nowSeconds,
      maxTotalWeight: MAX_TOTAL_WEIGHT,
    });
  }

  /**
   * `key` の有効な結果があれば返し、無ければ `load` で取得して格納する。
   *
   * `load` の失敗は伝播し、何も格納しない。重みが 1 件の上限を超える結果は返すが格納しない。
   * キャッシュヒットもスコープに保持されるため本文量を計上する。取得時の計上は `load` 側で行う。
   */
  async getOrLoad(
    key: string,
    load: () => Promise<Loaded<T>>,
    scope?: ResolutionWorkBudget,
  ): Promise<T> {
    const now = this.nowSeconds();
    const hit = this.cache.get(key, now);
    if (hit !== undefined && !hit.expired) {
      consumeResolutionBody(scope, hit.value.weight);
      return hit.value.value;
    }
    const loaded = await load();
    if (loaded.weight <= MAX_ENTRY_WEIGHT) {
      this.cache.set(key, loaded, RESOLUTION_CACHE_TTL_SECONDS, this.nowSeconds(), loaded.weight);
    }
    return loaded.value;
  }
}
