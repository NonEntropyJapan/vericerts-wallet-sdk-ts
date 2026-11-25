/**
 * SIOPv2 `vp_token id_token` ログインのテスト共通部品（vericerts-anchor 形式の要求・JWT の復号・署名鍵）。
 */

import { sha256 } from '@noble/hashes/sha2.js';
import { base64urlnopad } from '@scure/base';
import {
  getP256PublicKey,
  getSecp256k1PublicKey,
  verifyP256,
  verifySecp256k1,
} from '../../../keymanager/signer.js';

export const NOW = 1_700_000_000;
export const HOLDER_DID = 'did:key:zHolderLogin';
export const KID = `${HOLDER_DID}#zHolderLogin`;
export const CLIENT_ID = 'https://anchor.example.com/v1/login/authorization-responses';

/** vericerts-anchor の `createLoginRequest` が返す `authorization_request` と同じ形（`registration` なし）。 */
export function anchorRequest(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  const request: Record<string, unknown> = {
    response_type: 'vp_token id_token',
    response_mode: 'direct_post',
    client_id: CLIENT_ID,
    redirect_uri: CLIENT_ID,
    scope: 'openid',
    nonce: 'nonce-AbCdEf0123456789',
    state: 'state-0123456789AbCdEf',
    id_token_type: 'subject_signed_id_token',
    client_metadata: {
      subject_syntax_types_supported: ['did:key', 'did:web', 'did:jwk'],
      id_token_signing_alg_values_supported: ['ES256', 'ES256K'],
      vp_formats_supported: { jwt_vp: { alg_values: ['ES256', 'ES256K'] } },
    },
    ...overrides,
  };
  for (const key of Object.keys(overrides)) {
    if (overrides[key] === undefined) delete request[key];
  }
  return request;
}

export interface DecodedJwt {
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
  signingInput: string;
  signature: Uint8Array;
}

export function decodeJwt(jwt: string): DecodedJwt {
  const [h, p, s] = jwt.split('.');
  if (h === undefined || p === undefined || s === undefined) throw new Error('malformed jwt');
  const json = (segment: string) =>
    JSON.parse(Buffer.from(segment, 'base64url').toString('utf8')) as Record<string, unknown>;
  return {
    header: json(h),
    payload: json(p),
    signingInput: `${h}.${p}`,
    signature: base64urlnopad.decode(s),
  };
}

export const SIGNERS = [
  {
    alg: 'ES256' as const,
    privateKey: new Uint8Array(32).fill(11),
    verify: (jwt: DecodedJwt, privateKey: Uint8Array) =>
      verifyP256(
        sha256(new TextEncoder().encode(jwt.signingInput)),
        jwt.signature,
        getP256PublicKey(privateKey, false),
      ),
  },
  {
    alg: 'ES256K' as const,
    privateKey: new Uint8Array(32).fill(12),
    verify: (jwt: DecodedJwt, privateKey: Uint8Array) =>
      verifySecp256k1(
        sha256(new TextEncoder().encode(jwt.signingInput)),
        jwt.signature,
        getSecp256k1PublicKey(privateKey, false),
      ),
  },
];
