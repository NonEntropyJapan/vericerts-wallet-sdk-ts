/**
 * Type Metadata / スキーマ文書の TTL キャッシュ。
 *
 * 時刻は引数 `now` で受け取るため、呼び出し側が有効期限の判定時刻を制御できる。
 *
 * `vct` は VC 種別ごとに固定で、同一種別の VC を検証するたびに同じ URL を引くため、
 * TTL キャッシュがネットワーク往復を大きく削減する。
 *
 * 保持・失効・追い出しの実装は共有プリミティブ `UrlKeyedTtlCache`（`internal/cache`）に置く。
 * 本ファイルは Type Metadata 経路の既定 TTL を与えるだけの薄い派生であり、
 * `credentialSchema` 経路と実装を共有してもインスタンスは別なのでキャッシュ状態は混ざらない。
 *
 * セキュリティ上の注意:
 * - キーは URL 文字列そのもの（完全一致）のみとし、VC 由来の値を連結した複合キーは作らない。
 * - **エントリ数に上限を設ける**。キー（`vct` / `schema_uri`）は Issuer が自由に決められるため、
 *   毎回異なる URL のクレデンシャルを流されるとエントリが際限なく積み上がる（1 エントリ最大 1 MiB）。
 *   上限超過時は挿入順に古いものから捨てる（FIFO）。キャッシュはあくまで往復削減の最適化で、
 *   追い出しても再取得されるだけなので、追い出しによって判定が緩む経路は無い。
 */

import { DEFAULT_CACHE_MAX_ENTRIES, UrlKeyedTtlCache } from '../../../cache/index.js';
import { TYPE_METADATA_CACHE_TTL_MS } from './types.js';

/**
 * URL をキーに JSON 文書を TTL 保持する汎用キャッシュ。
 *
 * Type Metadata（`vct` URL）と JSON Schema（`schema_uri`）の双方に使う。
 */
export class TypeMetadataCache<T> extends UrlKeyedTtlCache<T> {
  /**
   * @param ttlMs キャッシュ TTL（ミリ秒、既定 5 分）。
   * @param maxEntries 保持する最大エントリ数（既定 `DEFAULT_CACHE_MAX_ENTRIES`）。
   */
  constructor(
    ttlMs: number = TYPE_METADATA_CACHE_TTL_MS,
    maxEntries: number = DEFAULT_CACHE_MAX_ENTRIES,
  ) {
    super(ttlMs, maxEntries);
  }
}
