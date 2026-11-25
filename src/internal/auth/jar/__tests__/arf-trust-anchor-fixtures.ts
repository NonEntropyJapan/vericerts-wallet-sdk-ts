/**
 * JAR 署名検証テスト用の ARF Trust Anchor Catalogue 組み立てヘルパー。
 *
 * `jar-signature.federation-arf.test.ts` と `jar-signature.arf-null-guards.test.ts` の双方が使う
 * ため共有する（Linterly 300 行/ファイル上限に収めるため後者へ分割した際に切り出した）。
 */

import { makeKeyPair, signedCatalogue } from '../../../trust/arf/__tests__/arf-fixtures.js';
import { loadArfTrustAnchor } from '../../../trust/arf/index.js';

/**
 * ARF Catalogue エンベロープ（署名検証済み）を組み立てる。エントリは呼び出し側が指定する。
 *
 * @param freshness 署名済み payload の任意の鮮度項目（`nextUpdate`）。
 */
export async function buildArfTrustAnchor(
  entries: Record<string, unknown>[],
  freshness: { readonly nextUpdate?: string } = {},
) {
  const key = makeKeyPair();
  const envelope = signedCatalogue({ entries, ...freshness }, key);
  return loadArfTrustAnchor('https://arf.example.eu/catalogue', {
    fetcher: async () => envelope,
    trustAnchorPublicKey: key.publicKey,
  });
}
