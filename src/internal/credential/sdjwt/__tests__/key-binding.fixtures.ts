/**
 * 分離型 Holder Service（Agent Holder）向け KB-JWT テンプレートテストの共有フィクスチャ。
 *
 * 想定する構成:
 * - Holder Service: VC バイト列を保管し、署名前テンプレートを返す。**Session 秘密鍵を保持しない。**
 * - Agent Session: 秘密鍵をプロセス内だけに持ち、`signingInput` に署名して返す。
 *
 * 実鍵を用い、モックは使わない（SDK のテスト方針）。
 */

import { expect } from 'bun:test';
import { type ErrorCode, VericertsError } from '../../../errors.js';
import type { PublicKeyJwk } from '../../../identity/did.js';
import { getP256PublicKey, getSecp256k1PublicKey } from '../../../keymanager/signer.js';
import type { CredentialAlg } from '../../vc/jws.js';
import { createPrivateKeySigner } from '../../vc/signer.js';
import { type ConfirmationClaim, createSdJwt } from '../sdjwt.js';

/** テスト用の固定 Issuer 秘密鍵。 */
export const ISSUER_KEY = new Uint8Array(32).fill(7);
/** Agent Session 鍵。Holder Service には渡らない前提。 */
export const SESSION_KEY = new Uint8Array(32).fill(11);
/** Session 鍵とは別の鍵（なりすまし検証用）。 */
export const OTHER_KEY = new Uint8Array(32).fill(13);

/** 非圧縮公開鍵（0x04 || x || y）から EC 公開鍵 JWK を構築する。 */
function toJwk(pub: Uint8Array, crv: string): PublicKeyJwk {
  const b64u = (b: Uint8Array): string => Buffer.from(b).toString('base64url');
  return { kty: 'EC', crv, x: b64u(pub.subarray(1, 33)), y: b64u(pub.subarray(33, 65)) };
}

export const ISSUER_JWK = toJwk(getP256PublicKey(ISSUER_KEY, false), 'P-256');
export const SESSION_JWK = toJwk(getSecp256k1PublicKey(SESSION_KEY, false), 'secp256k1');

export const VCT = 'https://example.com/credentials/identity';
export const CNF: ConfirmationClaim = { jwk: SESSION_JWK };
export const NONCE = 'verifier-nonce-1';
export const AUD = 'https://verifier.example/client';
export const IAT = 1_700_000_000;
export const SESSION_ALG = 'ES256K' as CredentialAlg;

export const ISSUER_SIGNER = createPrivateKeySigner(ISSUER_KEY, 'ES256');
export const SESSION_SIGNER = createPrivateKeySigner(SESSION_KEY, SESSION_ALG);
export const OTHER_SIGNER = createPrivateKeySigner(OTHER_KEY, SESSION_ALG);

/** 曲線不一致（P-256）の `cnf`。`SESSION_ALG`（ES256K）のテンプレートとは噛み合わない。 */
export const MISMATCHED_CRV_CNF: ConfirmationClaim = { jwk: ISSUER_JWK };

/**
 * Holder Service に保管される SD-JWT VC（既定の cnf = Agent Session 公開鍵）。
 *
 * `cnf` を差し替えると、曲線不一致など Key Binding が成立しないケースを再現できる。
 */
export function issue(cnf: ConfirmationClaim = CNF): string {
  return createSdJwt(ISSUER_SIGNER, {
    vct: VCT,
    issuer: 'did:example:issuer',
    cnf,
    disclosureClaims: ['name', 'age_over_18', 'email'],
    claims: {
      name: 'Alice',
      age_over_18: true,
      email: 'alice@example.com',
      sub: 'did:example:agent',
    },
    salts: { name: 'salt-name', age_over_18: 'salt-age', email: 'salt-email' },
    nowSeconds: IAT,
  });
}

/**
 * Agent Session 側の署名処理を模した関数。
 *
 * 受け取るのは `signingInput` だけで、VC バイト列には触れない（境界の再現）。
 */
export function signAsSession(signingInput: string, signer = SESSION_SIGNER): Uint8Array {
  return signer.sign(new TextEncoder().encode(signingInput));
}

/** signing input と raw 署名からコンパクト KB-JWT を組み立てる。 */
export function toCompactKbJwt(signingInput: string, signature: Uint8Array): string {
  return `${signingInput}.${Buffer.from(signature).toString('base64url')}`;
}

/** `VericertsError` の code を検査する。 */
export function expectCode(fn: () => unknown, code: ErrorCode): void {
  try {
    fn();
  } catch (error) {
    expect(error).toBeInstanceOf(VericertsError);
    expect((error as VericertsError).code).toBe(code);
    return;
  }
  throw new Error('例外が送出されなかった');
}
