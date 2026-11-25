/**
 * cache モジュールの公開エントリ。
 *
 * 対象リソースに依存しない TTL キャッシュのプリミティブ（`Cache-Control` 尊重・TTL 上限キャップ・
 * negative cache 30 秒固定）を再エクスポートする。
 *
 * あわせて、URL キー・単一固定 TTL（ミリ秒）・FIFO 上限のみの単純なキャッシュ
 * （`UrlKeyedTtlCache`）と、各キャッシュ層が既定の `nowSeconds` として使う実時計
 * （`systemNowSeconds`、 6 ファイルの重複実装を集約）も提供する。
 */

export { assertFiniteClock, systemNowSeconds } from './system-clock.js';
export {
  type CacheHit,
  type CacheState,
  createTtlCache,
  DEFAULT_CACHE_MAX_ENTRIES,
  NEGATIVE_CACHE_TTL_SECONDS,
  parseMaxAgeSeconds,
  resolveMaxTtlSeconds,
  STRING_CACHE_MAX_TOTAL_LENGTH,
  type TtlCache,
  type TtlCacheOptions,
} from './ttl-cache.js';
export { UrlKeyedTtlCache } from './url-keyed-ttl-cache.js';
