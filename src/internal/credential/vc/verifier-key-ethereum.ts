/**
 * 検証メソッドから Ethereum アドレスを取り出す（`alg: "ES256K-R"` の検証鍵）。
 *
 * did:pkh と did:ethr の controller 鍵の検証メソッドは公開鍵を持たず、`blockchainAccountId`（CAIP-10
 * `eip155:<chainId>:<address>`）だけを持つ（型 `EcdsaSecp256k1RecoveryMethod2020`）。検証側は署名（EIP-191）から公開鍵を
 * 復元し、そのアドレスと照合する。`ES256K-R` は IANA の JWS alg 登録外であり、2026-10-28 の「標準仕様だけで署名する」規則の
 * 例外。公開鍵を持つ検証メソッド（`publicKeyJwk` など）には使わない（標準の `ES256K` で扱う）。
 */

import type { VerificationMethod } from '../../identity/did.js';
import { ownProperty } from '../../prototype-safety/own-property.js';

/** 検証メソッドの型（`blockchainAccountId` を持つ secp256k1 復元型）。 */
export const ETHEREUM_RECOVERY_METHOD_TYPE = 'EcdsaSecp256k1RecoveryMethod2020';

const CAIP10_EIP155 = /^eip155:[0-9]{1,32}:(0x[0-9a-fA-F]{40})$/;

/**
 * 検証メソッドの `blockchainAccountId` から小文字の Ethereum アドレス（`0x` + 40 hex）を取り出す。
 *
 * 型が `EcdsaSecp256k1RecoveryMethod2020` で、`blockchainAccountId` が `eip155` の CAIP-10 のときだけ返す。
 * それ以外（別の名前空間・別の型・形式不正）は `undefined`。アドレスの大文字小文字（EIP-55）は区別しない。
 */
export function ethereumAddressOfMethod(method: VerificationMethod): string | undefined {
  if (ownProperty<unknown>(method, 'type') !== ETHEREUM_RECOVERY_METHOD_TYPE) {
    return undefined;
  }
  const accountId = ownProperty<unknown>(method, 'blockchainAccountId');
  if (typeof accountId !== 'string') {
    return undefined;
  }
  const match = CAIP10_EIP155.exec(accountId);
  return match === null ? undefined : (match[1] as string).toLowerCase();
}
