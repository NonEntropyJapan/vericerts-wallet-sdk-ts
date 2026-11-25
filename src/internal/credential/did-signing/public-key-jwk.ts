/**
 * 公開鍵 JWK の比較と、鍵種 → JWS `alg` の対応。`key-binding.ts` から分離した純粋関数。
 */

import { base64urlnopad } from '@scure/base';
import { ErrorCodes, VericertsError } from '../../errors.js';
import type { PublicKeyJwk } from '../../identity/did.js';
import { ownProperty } from '../../prototype-safety/own-property.js';
import type { CredentialAlg } from '../vc/jws.js';

/** JWK の曲線 → JWS `alg`。 */
const ALG_BY_CURVE: Readonly<Record<string, CredentialAlg>> = Object.assign(
  Object.create(null) as Record<string, CredentialAlg>,
  { 'P-256': 'ES256', secp256k1: 'ES256K', Ed25519: 'EdDSA' },
);

/**
 * 公開鍵 JWK から JWS `alg` を決める（EC P-256 → ES256 / EC secp256k1 → ES256K / OKP Ed25519 → EdDSA）。
 *
 * @throws 対応しない鍵の場合（VericertsError、code `1030`）。
 */
export function algForPublicKeyJwk(jwk: PublicKeyJwk): CredentialAlg {
  const kty = ownProperty<unknown>(jwk, 'kty');
  const crv = ownProperty<unknown>(jwk, 'crv');
  const alg = typeof crv === 'string' ? ALG_BY_CURVE[crv] : undefined;
  const expectedKty = alg === 'EdDSA' ? 'OKP' : 'EC';
  if (alg === undefined || kty !== expectedKty) {
    throw new VericertsError(ErrorCodes.UNSUPPORTED_ALGORITHM);
  }
  return alg;
}

/** base64url の公開鍵座標を比較用に正規化する（パディング差を吸収。不正なら `undefined`）。 */
function coordinate(value: unknown): string | undefined {
  if (typeof value !== 'string') {
    return undefined;
  }
  try {
    return base64urlnopad.encode(base64urlnopad.decode(value.replace(/=+$/, '')));
  } catch {
    return undefined;
  }
}

/** 2 つの公開鍵 JWK が同じ鍵か（kty / crv / x / y のみで比較。`kid` / `alg` / `use` などは見ない）。 */
export function samePublicKeyJwk(a: PublicKeyJwk, b: PublicKeyJwk): boolean {
  const kty = ownProperty<unknown>(a, 'kty');
  const crv = ownProperty<unknown>(a, 'crv');
  if (
    kty === undefined ||
    kty !== ownProperty<unknown>(b, 'kty') ||
    crv !== ownProperty<unknown>(b, 'crv')
  ) {
    return false;
  }
  const ax = coordinate(ownProperty<unknown>(a, 'x'));
  const ay = coordinate(ownProperty<unknown>(a, 'y'));
  return (
    ax !== undefined &&
    ax === coordinate(ownProperty<unknown>(b, 'x')) &&
    ay === coordinate(ownProperty<unknown>(b, 'y'))
  );
}
