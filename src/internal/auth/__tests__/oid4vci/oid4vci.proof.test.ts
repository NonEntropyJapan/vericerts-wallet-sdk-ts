/**
 * OID4VCI JWT Proof 生成（`generateProofJWT`）のユニットテスト（実鍵・モック禁止）。
 *
 * 検証内容:
 * - header が `{ typ: 'openid4vci-proof+jwt', alg, kid }`。
 * - payload が `{ iss, aud, iat, nonce }`（iat はエポック秒）。
 * - 署名が実鍵で検証可能（ES256 / ES256K / EdDSA）。
 * - nonce / audience / issuer / keyId が空なら HOLDER_PROOF_INVALID（3081）。
 */

import { describe, expect, it } from 'bun:test';
import { sha256 } from '@noble/hashes/sha2.js';
import type { CredentialAlg } from '../../../credential/vc/jws.js';
import { createPrivateKeySigner } from '../../../credential/vc/signer.js';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import { getEd25519PublicKey, verifyEd25519 } from '../../../keymanager/ed25519.js';
import {
  getP256PublicKey,
  getSecp256k1PublicKey,
  verifyP256,
  verifySecp256k1,
} from '../../../keymanager/signer.js';
import { generateProofJWT } from '../../oid4vci/oid4vci.js';

/** テスト用の固定秘密鍵。 */
const P256_KEY = new Uint8Array(32).fill(7);
const SECP_KEY = new Uint8Array(32).fill(9);
const ED_KEY = new Uint8Array(32).fill(5);

/** 固定現在時刻（ミリ秒）。iat = floor(NOW_MS / 1000)。 */
const NOW_MS = 1_767_225_600_123;
const EXPECTED_IAT = Math.floor(NOW_MS / 1000);

const NONCE = 'c-nonce-abc123';
const AUD = 'https://issuer.example.com/credential';
const ISS = 'did:ethr:0x1234';
const KID = 'did:ethr:0x1234#controller';

/** コンパクト JWS を 3 セグメントへ分解する（noUncheckedIndexedAccess 対応）。 */
function splitJwt(jwt: string): [string, string, string] {
  const parts = jwt.split('.');
  expect(parts).toHaveLength(3);
  return [parts[0] as string, parts[1] as string, parts[2] as string];
}

/** base64url 文字列を JSON object にデコードする。 */
function decodeSeg(seg: string): Record<string, unknown> {
  return JSON.parse(Buffer.from(seg, 'base64url').toString('utf8'));
}

/** alg ごとの鍵・検証関数（ECDSA は digest、EdDSA は signing-input を検証する）。 */
const FIXTURES: Record<
  CredentialAlg,
  {
    readonly privateKey: Uint8Array;
    readonly verify: (
      digest: Uint8Array,
      signature: Uint8Array,
      signingInput: Uint8Array,
    ) => boolean;
  }
> = {
  ES256: {
    privateKey: P256_KEY,
    verify: (digest, sig) => verifyP256(digest, sig, getP256PublicKey(P256_KEY, false)),
  },
  ES256K: {
    privateKey: SECP_KEY,
    verify: (digest, sig) => verifySecp256k1(digest, sig, getSecp256k1PublicKey(SECP_KEY, false)),
  },
  EdDSA: {
    privateKey: ED_KEY,
    // Ed25519 は digest ではなく signing-input を検証する。
    verify: (_digest, sig, signingInput) =>
      verifyEd25519(signingInput, sig, getEd25519PublicKey(ED_KEY)),
  },
};

describe.each<CredentialAlg>(['ES256', 'ES256K', 'EdDSA'])('generateProofJWT（%s）', (alg) => {
  const signer = createPrivateKeySigner(FIXTURES[alg].privateKey, alg);

  it('header が typ/alg/kid を持つ', () => {
    const jwt = generateProofJWT(
      { nonce: NONCE, audience: AUD, issuer: ISS, keyId: KID, now: NOW_MS },
      signer,
    );
    const [headerSeg] = splitJwt(jwt);
    const header = decodeSeg(headerSeg);
    expect(header.typ).toBe('openid4vci-proof+jwt');
    expect(header.alg).toBe(alg);
    expect(header.kid).toBe(KID);
  });

  it('payload が iss/aud/iat/nonce を持つ', () => {
    const jwt = generateProofJWT(
      { nonce: NONCE, audience: AUD, issuer: ISS, keyId: KID, now: NOW_MS },
      signer,
    );
    const [, payloadSeg] = splitJwt(jwt);
    const payload = decodeSeg(payloadSeg);
    expect(payload.iss).toBe(ISS);
    expect(payload.aud).toBe(AUD);
    expect(payload.nonce).toBe(NONCE);
    expect(payload.iat).toBe(EXPECTED_IAT);
  });

  it('署名が実鍵で検証可能', () => {
    const jwt = generateProofJWT(
      { nonce: NONCE, audience: AUD, issuer: ISS, keyId: KID, now: NOW_MS },
      signer,
    );
    const [headerSeg, payloadSeg, signatureSeg] = splitJwt(jwt);
    const signingInput = new TextEncoder().encode(`${headerSeg}.${payloadSeg}`);
    const digest = sha256(signingInput);
    const signature = new Uint8Array(Buffer.from(signatureSeg, 'base64url'));
    expect(FIXTURES[alg].verify(digest, signature, signingInput)).toBe(true);
  });
});

describe('generateProofJWT バリデーション', () => {
  const signer = createPrivateKeySigner(P256_KEY, 'ES256');
  const base = { nonce: NONCE, audience: AUD, issuer: ISS, keyId: KID, now: NOW_MS };

  it.each<[string, Record<string, string>]>([
    ['nonce', { nonce: '' }],
    ['audience', { audience: '  ' }],
    ['issuer', { issuer: '' }],
    ['keyId', { keyId: '' }],
  ])('%s が空なら HOLDER_PROOF_INVALID (3081)', (_label, override) => {
    try {
      generateProofJWT({ ...base, ...override }, signer);
      throw new Error('should have thrown');
    } catch (e) {
      expect(e).toBeInstanceOf(VericertsError);
      expect((e as VericertsError).code).toBe(ErrorCodes.HOLDER_PROOF_INVALID);
    }
  });

  it('now 省略時は Date.now() ベースの iat になる', () => {
    const before = Math.floor(Date.now() / 1000);
    const jwt = generateProofJWT({ nonce: NONCE, audience: AUD, issuer: ISS, keyId: KID }, signer);
    const after = Math.floor(Date.now() / 1000);
    const payload = decodeSeg(splitJwt(jwt)[1]);
    expect(typeof payload.iat).toBe('number');
    expect(payload.iat as number).toBeGreaterThanOrEqual(before);
    expect(payload.iat as number).toBeLessThanOrEqual(after);
  });
});
