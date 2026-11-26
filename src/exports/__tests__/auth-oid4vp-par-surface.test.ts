/**
 * OID4VP 経路の PAR の公開エクスポート面の回帰テスト。
 *
 * `auth-par-surface.test.ts`（OID4VCI 経路）と同じ観点を、型を共有しない
 * 本経路に対して個別に確認する。内部パス（`internal/auth/oid4vp-par/index.js`）から import すると
 * 公開面の欠落を検知できないため、必ず公開バレル（`@vericerts/vericerts-wallet-sdk/experimental`）経由で
 * import すること。
 */

import { describe, expect, test } from 'bun:test';
import * as sdk from '../../index.js';
import * as experimental from '../experimental.js';

const PAR_ENDPOINT = 'https://verifier.example.com/par';
const STATE = 'Zm9vYmFyLXN0YXRlLTEyOGJpdA';
const NONCE = 'n-0S6_WzA2Mj-0123456789';

const VALID_PAR_BODY = {
  request_uri: 'urn:ietf:params:oauth:request_uri:6esc_11ACC5bwc014ltc14eY22c',
  expires_in: 60,
} as const;

/** 成功レスポンスを返す fetch スタブ。送信 body を `calls` に記録する。 */
function stubFetchOk(calls: URLSearchParams[]): experimental.OID4VPPARRequest['fetchImpl'] {
  return async (_url, init) => {
    calls.push(new URLSearchParams(init.body));
    return new Response(JSON.stringify(VALID_PAR_BODY), {
      status: 201,
      headers: { 'Content-Type': 'application/json' },
    });
  };
}

describe('公開エクスポート: OID4VP 経路の PAR', () => {
  test('pushAuthorizationRequestForPresentation が experimental サブパスから import できる', () => {
    expect(typeof experimental.pushAuthorizationRequestForPresentation).toBe('function');
    // メインバレルには載らない。
    expect(
      (sdk as unknown as Record<string, unknown>).pushAuthorizationRequestForPresentation,
    ).toBeUndefined();
  });

  test('OID4VPPARRequest / OID4VPPARResponse が公開型として使え、実際に動作する', async () => {
    const calls: URLSearchParams[] = [];
    const req: experimental.OID4VPPARRequest = {
      par_endpoint: PAR_ENDPOINT,
      client_id: 'wallet-client',
      code_challenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
      state: STATE,
      nonce: NONCE,
      fetchImpl: stubFetchOk(calls),
    };

    const res: experimental.OID4VPPARResponse =
      await experimental.pushAuthorizationRequestForPresentation(req);
    expect(res.request_uri).toBe(VALID_PAR_BODY.request_uri);
    expect(res.expires_in).toBe(60);

    const body = calls[0];
    // OID4VCI の pushAuthorizationRequest とは異なる固定値・必須フィールドを実際に送る。
    expect(body?.get('response_type')).toBe('vp_token');
    expect(body?.get('client_id')).toBe('wallet-client');
    expect(body?.get('state')).toBe(STATE);
    expect(body?.get('nonce')).toBe(NONCE);
  });

  test('公開関数のエラーは OID4VCI とは別の公開エラーコードに正規化される（非 HTTPS エンドポイント）', async () => {
    const promise = experimental.pushAuthorizationRequestForPresentation({
      par_endpoint: 'http://verifier.example.com/par',
      client_id: 'wallet-client',
      code_challenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
      state: STATE,
      nonce: NONCE,
    });
    await expect(promise).rejects.toMatchObject({
      code: sdk.ErrorCodes.OID4VP_PAR_REQUEST_FAILED,
    });
  });
});
