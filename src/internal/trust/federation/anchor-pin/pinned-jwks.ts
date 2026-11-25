/**
 * OIDF Trust Anchor のピン留め鍵（JWK Set）の形状検査。
 *
 * SDK の `parsePinnedJwks`（`buildTrustChain` の入口）と、拡張の設定欄・`oidfVerdict` が**同じ基準**で
 * 判定するために、依存を `own-property` だけに絞って切り出した。拡張が `keys` の非空配列だけを見る別実装を
 * 持つと、形状不正な鍵が設定欄を通り、`buildTrustChain` の `TRUST_CHAIN_INVALID` が `not-found` に
 * 正規化されて「配下に無い」と誤診断される。
 */

import { ownProperty } from '../../../prototype-safety/own-property.js';
import type { JsonWebKeySet } from '../federation-types.js';

/** 鍵種別ごとの公開鍵素材メンバ（RFC 7638 §3.2 の必須メンバ）。 */
const KEY_MATERIAL_MEMBERS: Readonly<Record<string, readonly string[]>> = {
  EC: ['crv', 'x', 'y'],
  OKP: ['crv', 'x'],
  RSA: ['e', 'n'],
};

/** 鍵素材（`kty` + 必須メンバ）を直列化する。非対応の `kty` / 欠落があれば `undefined`。 */
export function keyMaterialOf(key: object): string | undefined {
  const kty = ownProperty<unknown>(key, 'kty');
  const members = typeof kty === 'string' ? KEY_MATERIAL_MEMBERS[kty] : undefined;
  if (typeof kty !== 'string' || members === undefined) {
    return undefined;
  }
  const values = members.map((member) => ownProperty<unknown>(key, member));
  return values.every((v) => typeof v === 'string')
    ? JSON.stringify([kty, ...(values as string[])])
    : undefined;
}

/** 値が「`keys` が非空配列で、全要素が鍵素材（`kty` + 必須メンバ）を読める JWK」の JWK Set か。 */
export function isPinnedJwkSet(value: unknown): value is JsonWebKeySet {
  const keys =
    typeof value === 'object' && value !== null ? ownProperty<unknown>(value, 'keys') : undefined;
  return (
    Array.isArray(keys) &&
    keys.length > 0 &&
    keys.every((key) => typeof key === 'object' && key !== null && keyMaterialOf(key) !== undefined)
  );
}
