export {
  type CacheHit,
  type CacheState,
  createTtlCache,
  DEFAULT_CACHE_MAX_ENTRIES,
  NEGATIVE_CACHE_TTL_SECONDS,
  resolveMaxTtlSeconds,
  type TtlCache,
  type TtlCacheOptions,
} from '../internal/cache/index.js';
