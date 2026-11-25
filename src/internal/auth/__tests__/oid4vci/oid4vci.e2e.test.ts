/**
 * OID4VCI Proof 生成 → Credential Endpoint 呼び出し → VC 受信のエンドツーエンドテスト。
 *
 * Token Response（access_token / c_nonce）取得後のフローを、
 * 実鍵で生成した Proof と注入 fetch で結合検証する:
 * - 生成した Proof が Credential Request に正しく載る。
 * - Issuer が Proof の nonce を確認したうえで VC を返す想定を再現し、生 VC 文字列を受信できる。
 */

import { describe, expect, it } from 'bun:test';
import { sha256 } from '@noble/hashes/sha2.js';
import { createPrivateKeySigner } from '../../../credential/vc/signer.js';
import { getP256PublicKey, verifyP256 } from '../../../keymanager/signer.js';
import { type FetchLike, generateProofJWT, requestCredential } from '../../oid4vci/oid4vci.js';

const HOLDER_KEY = new Uint8Array(32).fill(11);
const ENDPOINT = 'https://issuer.example.com/credential';
const C_NONCE = 'token-response-c-nonce';
const ACCESS_TOKEN = 'token-response-access-token';
const ISS = 'did:ethr:0xabc';
const KID = 'did:ethr:0xabc#controller';
const VC_JWT = 'eyJhbGciOiJFUzI1NiJ9.eyJ2YyI6eyJ0eXBlIjpbIlZDIl19fQ.signature';

describe('OID4VCI E2E（Proof 生成 → VC 受信）', () => {
  it('生成した Proof で VC を受信できる', async () => {
    const signer = createPrivateKeySigner(HOLDER_KEY, 'ES256');

    // ステップ 4: Token Response の c_nonce にバインドした Proof を生成。
    const proofJwt = generateProofJWT(
      { nonce: C_NONCE, audience: ENDPOINT, issuer: ISS, keyId: KID },
      signer,
    );

    // 注入 fetch で Issuer をシミュレート: Proof の nonce / aud / 署名を検証してから VC を返す。
    const fetchImpl: FetchLike = async (_url, init) => {
      const body = JSON.parse(init?.body as string);
      expect(body.proof.proof_type).toBe('jwt');
      const proofParts = (body.proof.jwt as string).split('.');
      expect(proofParts).toHaveLength(3);
      const [headerSeg, payloadSeg, sigSeg] = proofParts as [string, string, string];
      const payload = JSON.parse(Buffer.from(payloadSeg, 'base64url').toString('utf8'));
      // Issuer は nonce 一致と aud 一致を確認する。
      expect(payload.nonce).toBe(C_NONCE);
      expect(payload.aud).toBe(ENDPOINT);
      // 署名検証（実鍵）。
      const digest = sha256(new TextEncoder().encode(`${headerSeg}.${payloadSeg}`));
      const sig = new Uint8Array(Buffer.from(sigSeg, 'base64url'));
      expect(verifyP256(digest, sig, getP256PublicKey(HOLDER_KEY, false))).toBe(true);
      return new Response(JSON.stringify({ credential: VC_JWT }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      });
    };

    // ステップ 5: Credential Endpoint 呼び出し。
    const result = await requestCredential({
      credentialEndpoint: ENDPOINT,
      accessToken: ACCESS_TOKEN,
      format: 'jwt_vc_json',
      credentialDefinition: { type: ['VerifiableCredential'] },
      proofJwt,
      fetchImpl,
    });

    expect(result.status).toBe('issued');
    if (result.status === 'issued') {
      // 受信した生 VC 文字列を永続化・署名検証へ引き渡せる。
      expect(result.credential).toBe(VC_JWT);
    }
  });
});
