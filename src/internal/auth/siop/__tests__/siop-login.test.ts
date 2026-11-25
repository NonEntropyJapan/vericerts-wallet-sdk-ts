/**
 * DIDベース SIOPv2 の `vp_token id_token` ログイン（vericerts-anchor 形式）。
 *
 * 検証観点（anchor `verifyLogin`（src/credentials/login-verification.ts）が要求する形）:
 * - 要求は anchor の JSON オブジェクトのまま受け取れ、`registration` が無く `client_metadata` だけでも通る。
 * - `vp_token` は `typ=vp+jwt`・`kid`・`alg` つきで、ペイロードは VP そのもの（`vp` / `vc` クレームなし・
 *   VC なし・`@context[0]` が v2・`holder` / `nonce` / `aud` が id_token と一致）。
 * - `state` は保持され、`vp_token` を要求するのに `state` 等が欠ける要求は拒否される。
 * - P-256（ES256）と secp256k1（ES256K）のどちらの鍵でも、`kid` の DID が検証メソッドを指す署名になる。
 */

import { describe, expect, test } from 'bun:test';
import { createPrivateKeySigner } from '../../../credential/vc/signer.js';
import { processSIOPv2Request } from '../process.js';
import {
  anchorRequest,
  CLIENT_ID,
  decodeJwt,
  HOLDER_DID,
  KID,
  NOW,
  SIGNERS,
} from './siop-login.fixtures.js';

describe.each(SIGNERS)('anchor ログイン: $alg の鍵で vp_token と id_token を返す', (key) => {
  // `kid` つきの署名鍵（拡張の `withActiveSigner` が渡すものと同じ）。
  const signer = { ...createPrivateKeySigner(key.privateKey, key.alg), kid: KID };

  test('registration なし・client_metadata だけの anchor の JSON 要求が通り、両トークンが同じ DID・nonce・aud に結びつく', async () => {
    const response = await processSIOPv2Request(anchorRequest(), HOLDER_DID, signer, {
      nowSeconds: NOW,
    });

    expect(response.redirectUri).toBe(CLIENT_ID);
    expect(response.state).toBe('state-0123456789AbCdEf');
    if (response.vpToken === undefined) throw new Error('vp_token が返っていない');

    const idToken = decodeJwt(response.idToken);
    const vpToken = decodeJwt(response.vpToken);

    // id_token: iss = sub = DID、nonce、aud、iat、exp、kid 必須（anchor `verifyLogin`）。
    expect(idToken.header).toMatchObject({ alg: key.alg, kid: KID });
    expect(idToken.header.typ).not.toBe('vp+jwt');
    expect(idToken.payload).toMatchObject({
      iss: HOLDER_DID,
      sub: HOLDER_DID,
      nonce: 'nonce-AbCdEf0123456789',
      aud: CLIENT_ID,
      iat: NOW,
      exp: NOW + 300,
    });

    // vp_token: typ=vp+jwt・kid・alg、ペイロードは VC DM 2.0 の VP そのもの。
    expect(vpToken.header).toEqual({ alg: key.alg, kid: KID, typ: 'vp+jwt' });
    expect(vpToken.payload['@context']).toEqual(['https://www.w3.org/ns/credentials/v2']);
    expect(vpToken.payload.type).toContain('VerifiablePresentation');
    // vc-jose-cose §3.1.1: JWT の vp / vc クレームを持たない（anchor は拒否する）。
    expect('vp' in vpToken.payload).toBe(false);
    expect('vc' in vpToken.payload).toBe(false);
    // 資格を運ばない（anchor は空でない verifiableCredential を拒否する）。
    const credentials = vpToken.payload.verifiableCredential;
    expect(
      credentials === undefined || (Array.isArray(credentials) && credentials.length === 0),
    ).toBe(true);
    // holder = id_token の iss、nonce / aud も id_token と一致する。
    expect(vpToken.payload.holder).toBe(idToken.payload.iss);
    expect(vpToken.payload.nonce).toBe(idToken.payload.nonce);
    expect(vpToken.payload.aud).toBe(idToken.payload.aud);

    // どちらも署名鍵の公開鍵で検証できる。
    expect(key.verify(idToken, key.privateKey)).toBe(true);
    expect(key.verify(vpToken, key.privateKey)).toBe(true);
  });

  test('response_type が id_token だけの旧来の要求は vp_token も state も返さない', async () => {
    const response = await processSIOPv2Request(
      anchorRequest({
        response_type: 'id_token',
        response_mode: undefined,
        state: undefined,
        id_token_type: undefined,
      }),
      HOLDER_DID,
      signer,
      { nowSeconds: NOW },
    );
    expect(response.vpToken).toBeUndefined();
    expect(response.state).toBeUndefined();
  });
});
