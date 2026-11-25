/**
 * OID4VP 経路の PAR（Pushed Authorization Request）クライアントのテスト。
 *
 * `fetchImpl` をスタブして以下を検証する:
 * - PAR エンドポイント（Verifier）呼び出し: form-urlencoded のパラメータ送信とレスポンス mapping。
 * - `response_type=vp_token` / `code_challenge_method=S256` の固定送信。
 * - `nonce` が本経路固有の必須フィールドであること。
 * - DPoP proof の送出（body ではなく `DPoP` ヘッダ、RFC 9449 §5）。
 * - エラーレスポンス処理: HTTP 非 2xx / ネットワーク失敗 / JSON 不正 / 必須欠落 / 非 HTTPS。
 *
 * プロトタイプ汚染耐性・相関 ID 伝播は `oid4vp-par.security.test.ts` が担う。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import type { FetchLike } from '../../../fetch-di.js';
import { pushAuthorizationRequestForPresentation } from '../par.js';
import {
  baseRequest,
  type FetchCall,
  NONCE,
  PAR_ENDPOINT,
  STATE,
  stubFetchOk,
  stubFetchRaw,
  VALID_PAR_BODY,
  WALLET_ATTESTATION_ASSERTION_TYPE,
  WALLET_ATTESTATION_CLIENT_ASSERTION,
} from './oid4vp-par-fixtures.js';

describe('pushAuthorizationRequestForPresentation（PAR エンドポイント呼び出し）', () => {
  it('必須パラメータを form-urlencoded で送り request_uri / expires_in を mapping する', async () => {
    const calls: FetchCall[] = [];
    const res = await pushAuthorizationRequestForPresentation(
      baseRequest(stubFetchOk(VALID_PAR_BODY, calls)),
    );

    expect(res).toEqual({
      request_uri: VALID_PAR_BODY.request_uri,
      expires_in: 60,
    });

    expect(calls).toHaveLength(1);
    const call = calls[0];
    expect(call?.url).toBe(PAR_ENDPOINT);
    expect(call?.init.method).toBe('POST');
    expect(call?.init.headers['Content-Type']).toBe('application/x-www-form-urlencoded');
    // 提示要求の response_type は vp_token。
    expect(call?.body.get('response_type')).toBe('vp_token');
    expect(call?.body.get('client_id')).toBe('wallet-client');
    expect(call?.body.get('code_challenge')).toBe('E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM');
    expect(call?.body.get('code_challenge_method')).toBe('S256');
    expect(call?.body.get('state')).toBe(STATE);
    // nonce は本経路固有の必須フィールド。
    expect(call?.body.get('nonce')).toBe(NONCE);
    // OID4VCI 固有のフィールドは存在しない。
    expect(call?.body.has('redirect_uri')).toBe(false);
    expect(call?.body.has('scope')).toBe(false);
    expect(call?.body.has('authorization_details')).toBe(false);
  });

  it('client_assertion と client_assertion_type を対で指定すると両方が body に載る', async () => {
    const calls: FetchCall[] = [];
    await pushAuthorizationRequestForPresentation({
      ...baseRequest(stubFetchOk(VALID_PAR_BODY, calls)),
      client_assertion: WALLET_ATTESTATION_CLIENT_ASSERTION,
      client_assertion_type: WALLET_ATTESTATION_ASSERTION_TYPE,
    });

    const body = calls[0]?.body;
    expect(body?.get('client_assertion')).toBe(WALLET_ATTESTATION_CLIENT_ASSERTION);
    expect(body?.get('client_assertion_type')).toBe(WALLET_ATTESTATION_ASSERTION_TYPE);
  });

  it('client_assertion 無しで client_assertion_type だけ指定してもどちらも送らない', async () => {
    const calls: FetchCall[] = [];
    await pushAuthorizationRequestForPresentation({
      ...baseRequest(stubFetchOk(VALID_PAR_BODY, calls)),
      client_assertion_type: WALLET_ATTESTATION_ASSERTION_TYPE,
    });

    const body = calls[0]?.body;
    expect(body?.has('client_assertion')).toBe(false);
    expect(body?.has('client_assertion_type')).toBe(false);
  });

  it('省略可能パラメータ未指定時はそれらを送らない', async () => {
    const calls: FetchCall[] = [];
    await pushAuthorizationRequestForPresentation(baseRequest(stubFetchOk(VALID_PAR_BODY, calls)));

    const body = calls[0]?.body;
    expect(body?.has('client_assertion')).toBe(false);
    expect(body?.has('client_assertion_type')).toBe(false);
    expect(body?.get('state')).toBe(STATE);
    expect(body?.get('nonce')).toBe(NONCE);
  });

  it('expires_in が数値文字列でも受理する', async () => {
    const res = await pushAuthorizationRequestForPresentation(
      baseRequest(stubFetchOk({ ...VALID_PAR_BODY, expires_in: '90' }, [])),
    );
    expect(res.expires_in).toBe(90);
  });
});

describe('DPoP proof の送出（RFC 9449 §5）', () => {
  const PROOF = 'eyJ0eXAiOiJkcG9wK2p3dCJ9.eyJodG0iOiJQT1NUIn0.c2ln';

  it('dpop 指定時は body ではなく DPoP ヘッダに載せる', async () => {
    const calls: FetchCall[] = [];
    await pushAuthorizationRequestForPresentation({
      ...baseRequest(stubFetchOk(VALID_PAR_BODY, calls)),
      dpop: PROOF,
    });
    const call = calls[0];
    expect(call?.init.headers.DPoP).toBe(PROOF);
    expect(call?.body.has('dpop')).toBe(false);
  });

  it('dpop 未指定なら DPoP ヘッダ自体を出さない', async () => {
    const calls: FetchCall[] = [];
    await pushAuthorizationRequestForPresentation(baseRequest(stubFetchOk(VALID_PAR_BODY, calls)));
    expect(Object.hasOwn(calls[0]?.init.headers ?? {}, 'DPoP')).toBe(false);
  });

  it.each([
    ['空文字', ''],
    ['空白のみ', '   '],
  ])('dpop が%sなら OID4VP_PAR_REQUEST_FAILED(8031) で弾き fetch を呼ばない', async (_, dpop) => {
    const calls: FetchCall[] = [];
    const promise = pushAuthorizationRequestForPresentation({
      ...baseRequest(stubFetchOk(VALID_PAR_BODY, calls)),
      dpop,
    });
    await expect(promise).rejects.toMatchObject({ code: ErrorCodes.OID4VP_PAR_REQUEST_FAILED });
    expect(calls).toHaveLength(0);
  });
});

describe('必須フィールドの非空ガード', () => {
  it.each([
    ['state', '空文字', ''],
    ['state', '空白のみ', '   '],
    ['code_challenge', '空文字', ''],
    ['code_challenge', '空白のみ', '   '],
    ['nonce', '空文字', ''],
    ['nonce', '空白のみ', '   '],
  ])('%s が%sなら 8031 で弾き fetch を呼ばない', async (field, _label, value) => {
    const calls: FetchCall[] = [];
    const promise = pushAuthorizationRequestForPresentation({
      ...baseRequest(stubFetchOk(VALID_PAR_BODY, calls)),
      [field]: value,
    });
    await expect(promise).rejects.toMatchObject({ code: ErrorCodes.OID4VP_PAR_REQUEST_FAILED });
    expect(calls).toHaveLength(0);
  });

  it.each([
    ['未指定', undefined],
    ['空文字', ''],
    ['空白のみ', '   '],
  ])('client_assertion 指定時に client_assertion_type が%sなら 8031 で弾き fetch を呼ばない', async (_, clientAssertionType) => {
    const calls: FetchCall[] = [];
    const promise = pushAuthorizationRequestForPresentation({
      ...baseRequest(stubFetchOk(VALID_PAR_BODY, calls)),
      client_assertion: WALLET_ATTESTATION_CLIENT_ASSERTION,
      client_assertion_type: clientAssertionType,
    });
    await expect(promise).rejects.toMatchObject({ code: ErrorCodes.OID4VP_PAR_REQUEST_FAILED });
    expect(calls).toHaveLength(0);
  });
});

describe('エラーレスポンス処理', () => {
  it('非 HTTPS の PAR エンドポイントは OID4VP_PAR_REQUEST_FAILED(8031) になる', async () => {
    const calls: FetchCall[] = [];
    const promise = pushAuthorizationRequestForPresentation({
      ...baseRequest(stubFetchOk(VALID_PAR_BODY, calls)),
      par_endpoint: 'http://verifier.example.com/par',
    });
    await expect(promise).rejects.toMatchObject({ code: ErrorCodes.OID4VP_PAR_REQUEST_FAILED });
    expect(calls).toHaveLength(0);
  });

  it('HTTP 400（OAuth エラー）は OID4VP_PAR_REQUEST_FAILED(8031) になる', async () => {
    const promise = pushAuthorizationRequestForPresentation(
      baseRequest(stubFetchRaw(JSON.stringify({ error: 'invalid_request' }), 400)),
    );
    await expect(promise).rejects.toBeInstanceOf(VericertsError);
    await expect(promise).rejects.toMatchObject({ code: ErrorCodes.OID4VP_PAR_REQUEST_FAILED });
  });

  it('ネットワーク失敗は OID4VP_PAR_REQUEST_FAILED(8031, 再試行可) になる', async () => {
    const failingFetch: FetchLike = async () => {
      throw new TypeError('network down');
    };
    const promise = pushAuthorizationRequestForPresentation(baseRequest(failingFetch));
    await expect(promise).rejects.toMatchObject({
      code: ErrorCodes.OID4VP_PAR_REQUEST_FAILED,
      retriable: true,
    });
  });

  it('レスポンス JSON が不正な場合は 8031 になる', async () => {
    const promise = pushAuthorizationRequestForPresentation(
      baseRequest(stubFetchRaw('not-json', 201)),
    );
    await expect(promise).rejects.toMatchObject({ code: ErrorCodes.OID4VP_PAR_REQUEST_FAILED });
  });

  it('request_uri 欠落は 8031 になる', async () => {
    const promise = pushAuthorizationRequestForPresentation(
      baseRequest(stubFetchRaw(JSON.stringify({ expires_in: 60 }), 201)),
    );
    await expect(promise).rejects.toMatchObject({ code: ErrorCodes.OID4VP_PAR_REQUEST_FAILED });
  });

  it('expires_in 欠落 / 非数値は 8031 になる', async () => {
    const promise = pushAuthorizationRequestForPresentation(
      baseRequest(
        stubFetchRaw(JSON.stringify({ request_uri: 'urn:req:1', expires_in: 'soon' }), 201),
      ),
    );
    await expect(promise).rejects.toMatchObject({ code: ErrorCodes.OID4VP_PAR_REQUEST_FAILED });
  });
});
