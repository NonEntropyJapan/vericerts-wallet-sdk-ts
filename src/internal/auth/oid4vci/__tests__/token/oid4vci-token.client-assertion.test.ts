/**
 * Token Request が送る `client_assertion` の形式の回帰テスト。
 *
 * PAR と Token Request の両方で同じ client assertion 形式 `<WUA>~<WUA-PoP>` を使う。
 *
 * ここでは `oid4vci-par.client-assertion.test.ts` と同じ流儀で、唯一の生成箇所である
 * `buildClientAttestation`（`internal/eudi/wua/proof.ts`）が組み立てた連結形が Token Request の
 * body へそのまま（`~` 区切りを保ち WUA JWT 部・PoP 部の両方を残して）送出され、Token 経路専用の
 * 変換・分解・切り出しが入り込まないことを検証する。
 *
 * 本ファイルは `fetchImpl` DI シーム追加より前に書かれており、グローバル `fetch` を
 * 差し替え `afterEach` で必ず復元する形を採る。未注入時の既定経路（グローバル `fetch`）を通す
 * 回帰テストとしてこの形のまま残す。DI シーム自体の検証は `oid4vci-token.fetch-di.test.ts`。
 */

import { afterEach, describe, expect, it } from 'bun:test';
import { makeWuaJwt, wscdSigner } from '../../../../eudi/wua/__tests__/wua-fixtures.js';
import { buildClientAttestation, buildWuaProofOfPossession } from '../../../../eudi/wua/proof.js';
import { WUA_CLIENT_ASSERTION_TYPE } from '../../../../eudi/wua/types.js';
import { parseWalletUnitAttestation } from '../../../../eudi/wua/wua.js';
import { requestTokenAuthorizationCode } from '../../token/oid4vci-token.js';

/** テスト用の Token Endpoint（`client_assertion` 指定時は HTTPS 必須）。 */
const TOKEN_ENDPOINT = 'https://issuer.example.com/token';

/** WUA を署名する Wallet Provider 相当の鍵（`proof.test.ts` と同値）。 */
const PROVIDER_KEY = new Uint8Array(32).fill(3);

/** WUA-PoP の `iat` を固定するための基準時刻。 */
const NOW = 1_712_400_000;

/** AS が返す正常な Token 応答。 */
const VALID_TOKEN_BODY = {
  access_token: 'eyJhbGci.access.token',
  token_type: 'Bearer',
  expires_in: 3600,
  c_nonce: 'tZignsnFbp',
  c_nonce_expires_in: 86400,
} as const;

const originalFetch = globalThis.fetch;

afterEach(() => {
  globalThis.fetch = originalFetch;
});

describe('Token Request は buildClientAttestation の <WUA>~<WUA-PoP> をそのまま送る', () => {
  it('client_assertion は WUA JWT 部と PoP 部を `~` で連結したまま body に載る', async () => {
    const wua = parseWalletUnitAttestation(makeWuaJwt(PROVIDER_KEY));
    const pop = buildWuaProofOfPossession(
      wua,
      { aud: TOKEN_ENDPOINT, nonce: 'c_nonce_123', jti: '9f3c1f0e-6a52-4f8e-9b2d-7c1a5d3e4b10' },
      wscdSigner(),
      NOW,
    );
    const attestation = buildClientAttestation(wua, pop);

    const bodies: URLSearchParams[] = [];
    globalThis.fetch = (async (_url: string, init: RequestInit) => {
      bodies.push(new URLSearchParams(init.body as string));
      return new Response(JSON.stringify(VALID_TOKEN_BODY), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      });
    }) as unknown as typeof fetch;

    await requestTokenAuthorizationCode(TOKEN_ENDPOINT, {
      code: 'auth-code-123',
      codeVerifier: 'verifier-xyz',
      clientAssertion: attestation.clientAssertion,
      clientAssertionType: attestation.clientAssertionType,
    });

    const sent = bodies[0]?.get('client_assertion');
    // PAR 経路が使う値と 1 文字も違わないこと。
    expect(sent).toBe(`${wua.jwt}~${pop}`);
    // 連結形が保たれている（PoP 単独へ切り詰められていない）こと。
    expect(sent?.split('~')).toEqual([wua.jwt, pop]);
    expect(bodies[0]?.get('client_assertion_type')).toBe(WUA_CLIENT_ASSERTION_TYPE);
    expect(attestation.clientAssertionType).toBe(WUA_CLIENT_ASSERTION_TYPE);
  });
});
