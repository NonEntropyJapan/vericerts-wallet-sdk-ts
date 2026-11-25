// SD-JWT 検証のハードニング回帰テスト群（sdjwt.hardening.test.ts の分割）が共有する
// 鍵・定数・発行ヘルパ。実鍵のみを使い、モックは使わない（テスト方針は各 *.test.ts の冒頭参照）。

import type { PublicKeyJwk } from '../../../../identity/did.js';
import { getP256PublicKey, getSecp256k1PublicKey } from '../../../../keymanager/signer.js';
import type { CredentialAlg } from '../../../vc/jws.js';
import { createPrivateKeySigner } from '../../../vc/signer.js';
import { createSdJwt } from '../../sdjwt.js';

/** 非圧縮公開鍵（0x04 || x || y）から EC 公開鍵 JWK を構築する。 */
function toJwk(pub: Uint8Array, crv: string): PublicKeyJwk {
  const b64u = (b: Uint8Array): string => Buffer.from(b).toString('base64url');
  return { kty: 'EC', crv, x: b64u(pub.subarray(1, 33)), y: b64u(pub.subarray(33, 65)) };
}

export const ISSUER_KEY = new Uint8Array(32).fill(7);
export const HOLDER_KEY = new Uint8Array(32).fill(11);
export const ISSUER_JWK = toJwk(getP256PublicKey(ISSUER_KEY, false), 'P-256');
export const HOLDER_JWK = toJwk(getSecp256k1PublicKey(HOLDER_KEY, false), 'secp256k1');
export const ISSUER_SIGNER = createPrivateKeySigner(ISSUER_KEY, 'ES256');
export const HOLDER_SIGNER = createPrivateKeySigner(HOLDER_KEY, 'ES256K' as CredentialAlg);
export const VCT = 'https://example.com/credentials/identity';
/** 発行時刻（各テストの検証時刻 `IAT` 以下に固定し、未来 `iat` の 4014 を避ける）。 */
export const ISSUED_AT = 1_000_000;

/** cnf / status / 開示クレームを含む SD-JWT を発行する。 */
export function issue(): string {
  return createSdJwt(ISSUER_SIGNER, {
    vct: VCT,
    cnf: { jwk: HOLDER_JWK },
    status: { status_list: { idx: 42, uri: 'https://issuer.example/status/1' } },
    disclosureClaims: ['name'],
    claims: { name: 'Alice' },
    salts: { name: 'salt-name' },
    nowSeconds: ISSUED_AT,
  });
}

/** 既存 issuer 署名鍵で payload を差し替えて再署名し、有効署名の改竄 SD-JWT を作る。 */
export function reissueWithPayload(
  payload: Record<string, unknown>,
  disclosures: readonly string[],
): string {
  const b64uText = (t: string): string => Buffer.from(t).toString('base64url');
  const header = b64uText(JSON.stringify({ alg: 'ES256', typ: 'vc+sd-jwt' }));
  const body = b64uText(JSON.stringify(payload));
  const signingInput = `${header}.${body}`;
  const sig = ISSUER_SIGNER.sign(new TextEncoder().encode(signingInput));
  const issuerJwt = `${signingInput}.${Buffer.from(sig).toString('base64url')}`;
  const ds = disclosures.join('~');
  return ds.length > 0 ? `${issuerJwt}~${ds}~` : `${issuerJwt}~`;
}
