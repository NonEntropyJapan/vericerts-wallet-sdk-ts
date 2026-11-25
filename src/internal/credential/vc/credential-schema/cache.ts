/**
 * `credentialSchema` から取得した JSON Schema 文書の TTL キャッシュ。
 *
 * `sdjwt/type-metadata/cache.ts` と同じ設計方針
 * （`now` を引数で受け取り内部で `Date.now()` を呼ばない = テストの決定性）に揃える。
 * Type Metadata 経路とは別エコシステムのため、キャッシュも独立させて相互汚染を避ける。
 *
 * 保持・失効・追い出しの実装は共有プリミティブ `UrlKeyedTtlCache`（`internal/cache`）に置く。
 * 実装を共有してもインスタンスは呼び出し側ごとに生成されるため、Type Metadata 経路と
 * キャッシュ状態が混ざることはない（独立性は保たれる）。
 *
 * セキュリティ上の注意:
 * - キーは**スキーマ URL 文字列そのもの**のみとする。VC 由来の値（issuer / vct / claim 等）を
 *   連結した複合キーにすると、区切り文字を含む値でキー衝突を作られスキーマをすり替えられる。
 * - **エントリ数に上限を設ける**。スキーマ URL は Issuer が自由に決められるため、毎回異なる URL の
 *   VC を流されるとエントリが際限なく積み上がる（1 エントリ最大 1 MiB）。上限超過時は挿入順に
 *   古いものから捨てる（FIFO）。キャッシュは往復削減の最適化にすぎず、追い出されても再取得される
 *   だけなので、追い出しによって検証が緩む経路は無い。
 */

import { DEFAULT_CACHE_MAX_ENTRIES, UrlKeyedTtlCache } from '../../../cache/index.js';
import type { JsonSchema } from '../../json-schema/index.js';
import { CREDENTIAL_SCHEMA_CACHE_TTL_MS } from './types.js';

/** スキーマ URL をキーに JSON Schema 文書を TTL 保持するキャッシュ。 */
export class CredentialSchemaCache extends UrlKeyedTtlCache<JsonSchema> {
  /**
   * @param ttlMs キャッシュ TTL（ミリ秒、既定 5 分）。
   * @param maxEntries 保持する最大エントリ数（既定 `DEFAULT_CACHE_MAX_ENTRIES`）。
   */
  constructor(
    ttlMs: number = CREDENTIAL_SCHEMA_CACHE_TTL_MS,
    maxEntries: number = DEFAULT_CACHE_MAX_ENTRIES,
  ) {
    super(ttlMs, maxEntries);
  }
}
