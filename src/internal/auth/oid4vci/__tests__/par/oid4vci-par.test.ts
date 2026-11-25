/**
 * OID4VCI PAR（Pushed Authorization Request）クライアントのテスト。
 *
 * `fetchImpl` をスタブして以下を検証する:
 * - PAR エンドポイント呼び出し: form-urlencoded のパラメータ送信とレスポンス mapping。
 * - DPoP proof の送出: `dpop` は body ではなく `DPoP` ヘッダに載る（RFC 9449 §5）。
 * - エラーレスポンス処理: HTTP 非 2xx / ネットワーク失敗 / JSON 不正 / 必須欠落 / 非 HTTPS。
 *
 * 認可 URL 構築（`buildAuthorizationUrl`）は `oid4vci-authz-url.test.ts` が担う。
 */

import { describe, expect, it } from 'bun:test';
import { withPollutedPrototypeAsync } from '../../../../__tests__/prototype-pollution.fixtures.js';
import { ErrorCodes, VericertsError } from '../../../../errors.js';
import type { FetchLike } from '../../oid4vci.js';
import type { OAuth2AuthzDetails } from '../../par/index.js';
import { pushAuthorizationRequest } from '../../par/index.js';
import {
  baseRequest,
  type FetchCall,
  PAR_ENDPOINT,
  STATE,
  stubFetchOk,
  stubFetchRaw,
  VALID_PAR_BODY,
  WALLET_ATTESTATION_ASSERTION_TYPE,
  WALLET_ATTESTATION_CLIENT_ASSERTION,
} from './par-fixtures.js';

describe('pushAuthorizationRequest（PAR エンドポイント呼び出し）', () => {
  it('必須パラメータを form-urlencoded で送り request_uri / expires_in を mapping する', async () => {
    const calls: FetchCall[] = [];
    const res = await pushAuthorizationRequest(baseRequest(stubFetchOk(VALID_PAR_BODY, calls)));

    expect(res).toEqual({
      request_uri: VALID_PAR_BODY.request_uri,
      expires_in: 60,
    });

    expect(calls).toHaveLength(1);
    const call = calls[0];
    expect(call?.url).toBe(PAR_ENDPOINT);
    expect(call?.init.method).toBe('POST');
    expect(call?.init.headers['Content-Type']).toBe('application/x-www-form-urlencoded');
    expect(call?.body.get('response_type')).toBe('code');
    expect(call?.body.get('client_id')).toBe('wallet-client');
    expect(call?.body.get('code_challenge')).toBe('E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM');
    expect(call?.body.get('code_challenge_method')).toBe('S256');
    expect(call?.body.get('redirect_uri')).toBe('com.example.wallet://cb');
    // state は CSRF 防止のため必須で、常に body に載る。
    expect(call?.body.get('state')).toBe(STATE);
  });

  it('scope / authorization_details / state / client_assertion を送る', async () => {
    const calls: FetchCall[] = [];
    await pushAuthorizationRequest({
      ...baseRequest(stubFetchOk(VALID_PAR_BODY, calls)),
      scope: 'UniversityDegree',
      authorization_details: [{ type: 'openid_credential', credential_configuration_id: 'deg' }],
      state: 'state-128bit',
      client_assertion_type: WALLET_ATTESTATION_ASSERTION_TYPE,
      client_assertion: WALLET_ATTESTATION_CLIENT_ASSERTION,
    });

    const body = calls[0]?.body;
    expect(body?.get('scope')).toBe('UniversityDegree');
    expect(body?.get('authorization_details')).toBe(
      JSON.stringify([{ type: 'openid_credential', credential_configuration_id: 'deg' }]),
    );
    expect(body?.get('state')).toBe('state-128bit');
    expect(body?.get('client_assertion_type')).toBe(WALLET_ATTESTATION_ASSERTION_TYPE);
    expect(body?.get('client_assertion')).toBe(WALLET_ATTESTATION_CLIENT_ASSERTION);
  });

  // state は CSRF 防止のために必要。128 bit 以上の乱数から生成し、リダイレクト受領時に完全一致を確認する。
  // 空の state を許すと照合が
  // 無意味になるため push 前に 8010 で弾き、平文 body を送信しない。
  it.each([
    ['空文字', ''],
    ['空白のみ', '   '],
  ])('state が%sの場合は TOKEN_REQUEST_FAILED(8010) で弾き fetch を呼ばない', async (_, state) => {
    const calls: FetchCall[] = [];
    const promise = pushAuthorizationRequest({
      ...baseRequest(stubFetchOk(VALID_PAR_BODY, calls)),
      state,
    });
    await expect(promise).rejects.toMatchObject({ code: ErrorCodes.TOKEN_REQUEST_FAILED });
    expect(calls).toHaveLength(0);
  });

  // RFC 7521 §4.2 は client_assertion 使用時に client_assertion_type を REQUIRED と定める。
  // SDK はクライアント認証方式を
  // 補完せず呼び出し側に明示させる。`client_assertion` に渡された値が Wallet Attestation なのか
  // RFC 7523 の `jwt-bearer` assertion なのかを SDK からは判別できず、既定値を補うと別形式の
  // assertion を Wallet Attestation として誤ってラベル付けして送信しうるため。未指定は push 前に 8010。
  it.each([
    ['未指定', undefined],
    ['空文字', ''],
    ['空白のみ', '   '],
  ])('client_assertion 指定時に client_assertion_type が%sなら 8010 で弾き fetch を呼ばない', async (_, clientAssertionType) => {
    const calls: FetchCall[] = [];
    const promise = pushAuthorizationRequest({
      ...baseRequest(stubFetchOk(VALID_PAR_BODY, calls)),
      client_assertion: WALLET_ATTESTATION_CLIENT_ASSERTION,
      client_assertion_type: clientAssertionType,
    });
    await expect(promise).rejects.toMatchObject({ code: ErrorCodes.TOKEN_REQUEST_FAILED });
    expect(calls).toHaveLength(0);
  });

  it('client_assertion と client_assertion_type を対で指定すると両方が body に載る', async () => {
    const calls: FetchCall[] = [];
    await pushAuthorizationRequest({
      ...baseRequest(stubFetchOk(VALID_PAR_BODY, calls)),
      client_assertion: WALLET_ATTESTATION_CLIENT_ASSERTION,
      client_assertion_type: WALLET_ATTESTATION_ASSERTION_TYPE,
    });

    const body = calls[0]?.body;
    expect(body?.get('client_assertion')).toBe(WALLET_ATTESTATION_CLIENT_ASSERTION);
    expect(body?.get('client_assertion_type')).toBe(WALLET_ATTESTATION_ASSERTION_TYPE);
  });

  // client_assertion が無いのに type だけ送っても AS 側で解釈できず無意味なため送らない。
  it('client_assertion 無しで client_assertion_type だけ指定してもどちらも送らない', async () => {
    const calls: FetchCall[] = [];
    await pushAuthorizationRequest({
      ...baseRequest(stubFetchOk(VALID_PAR_BODY, calls)),
      client_assertion_type: WALLET_ATTESTATION_ASSERTION_TYPE,
    });

    const body = calls[0]?.body;
    expect(body?.has('client_assertion')).toBe(false);
    expect(body?.has('client_assertion_type')).toBe(false);
  });

  // `OAuth2AuthzDetails` は `type` のみ必須で、他メンバは
  // 認可タイプごとに定義される「不透明パススルー」。SDK が `type` 以外を検証・正規化・削除
  // しないことを固定する（メンバを落とすと AS が受理する正当な認可詳細を Wallet 側で潰す）。
  it('OAuth2AuthzDetails は type 以外のメンバを検証も正規化もせずそのまま送る', async () => {
    const calls: FetchCall[] = [];
    // `type` 必須は型で担保する（このリテラルから `type` を消すと型エラーになる）。
    const details: readonly OAuth2AuthzDetails[] = [
      {
        type: 'openid_credential',
        credential_configuration_id: 'UniversityDegree',
        credential_identifiers: ['deg-1', 'deg-2'],
        locations: ['https://issuer.example.com'],
        // SDK が知らない将来メンバ / 入れ子オブジェクトも素通しする。
        vendor_ext: { nested: { deep: 1 } },
      },
      { type: 'urn:example:other' },
    ];

    await pushAuthorizationRequest({
      ...baseRequest(stubFetchOk(VALID_PAR_BODY, calls)),
      authorization_details: details,
    });

    // 配列の順序・件数・各メンバがそのまま JSON 化される（脱落・並べ替え・既定値補完なし）。
    expect(calls[0]?.body.get('authorization_details')).toBe(JSON.stringify(details));
  });

  it('省略可能パラメータ未指定時はそれらを送らない', async () => {
    const calls: FetchCall[] = [];
    await pushAuthorizationRequest(baseRequest(stubFetchOk(VALID_PAR_BODY, calls)));

    const body = calls[0]?.body;
    expect(body?.has('scope')).toBe(false);
    expect(body?.has('authorization_details')).toBe(false);
    expect(body?.has('client_assertion')).toBe(false);
    expect(body?.has('client_assertion_type')).toBe(false);
    // state は必須なので「未指定時に送らない」対象ではない。
    expect(body?.get('state')).toBe(STATE);
  });

  it('expires_in が数値文字列でも受理する', async () => {
    const calls: FetchCall[] = [];
    const res = await pushAuthorizationRequest(
      baseRequest(stubFetchOk({ ...VALID_PAR_BODY, expires_in: '90' }, calls)),
    );
    expect(res.expires_in).toBe(90);
  });
});

describe('エラーレスポンス処理', () => {
  it('非 HTTPS の PAR エンドポイントは TOKEN_REQUEST_FAILED(8010) になる', async () => {
    const calls: FetchCall[] = [];
    const promise = pushAuthorizationRequest({
      ...baseRequest(stubFetchOk(VALID_PAR_BODY, calls)),
      par_endpoint: 'http://issuer.example.com/par',
    });
    await expect(promise).rejects.toMatchObject({ code: ErrorCodes.TOKEN_REQUEST_FAILED });
    // HTTPS 違反時は fetch を呼ばない（client_assertion を平文送信しない）。
    expect(calls).toHaveLength(0);
  });

  it('HTTP 400（OAuth エラー）は TOKEN_REQUEST_FAILED(8010) になる', async () => {
    const promise = pushAuthorizationRequest({
      ...baseRequest(stubFetchRaw(JSON.stringify({ error: 'invalid_request' }), 400)),
    });
    await expect(promise).rejects.toBeInstanceOf(VericertsError);
    await expect(promise).rejects.toMatchObject({ code: ErrorCodes.TOKEN_REQUEST_FAILED });
  });

  it('ネットワーク失敗は ISSUER_COMMUNICATION_FAILED(3004, 再試行可) になる', async () => {
    const failingFetch: FetchLike = async () => {
      throw new TypeError('network down');
    };
    const promise = pushAuthorizationRequest(baseRequest(failingFetch));
    await expect(promise).rejects.toMatchObject({
      code: ErrorCodes.ISSUER_COMMUNICATION_FAILED,
      retriable: true,
    });
  });

  it('レスポンス JSON が不正な場合は TOKEN_REQUEST_FAILED(8010) になる', async () => {
    const promise = pushAuthorizationRequest(baseRequest(stubFetchRaw('not-json', 201)));
    await expect(promise).rejects.toMatchObject({ code: ErrorCodes.TOKEN_REQUEST_FAILED });
  });

  it('request_uri 欠落は TOKEN_REQUEST_FAILED(8010) になる', async () => {
    const promise = pushAuthorizationRequest(
      baseRequest(stubFetchRaw(JSON.stringify({ expires_in: 60 }), 201)),
    );
    await expect(promise).rejects.toMatchObject({ code: ErrorCodes.TOKEN_REQUEST_FAILED });
  });

  it('expires_in 欠落 / 非数値は TOKEN_REQUEST_FAILED(8010) になる', async () => {
    const promise = pushAuthorizationRequest(
      baseRequest(
        stubFetchRaw(JSON.stringify({ request_uri: 'urn:req:1', expires_in: 'soon' }), 201),
      ),
    );
    await expect(promise).rejects.toMatchObject({ code: ErrorCodes.TOKEN_REQUEST_FAILED });
  });
});

describe('DPoP proof の送出（RFC 9449 §5）', () => {
  const PROOF = 'eyJ0eXAiOiJkcG9wK2p3dCJ9.eyJodG0iOiJQT1NUIn0.c2ln';

  it('dpop 指定時は body ではなく DPoP ヘッダに載せる', async () => {
    const calls: FetchCall[] = [];
    await pushAuthorizationRequest({
      ...baseRequest(stubFetchOk(VALID_PAR_BODY, calls)),
      dpop: PROOF,
    });
    const call = calls[0];
    expect(call?.init.headers.DPoP).toBe(PROOF);
    // RFC 9449 §5 は proof を HTTP ヘッダで送ると定める。body に混ぜてはならない。
    expect(call?.body.has('dpop')).toBe(false);
  });

  it('dpop 未指定なら DPoP ヘッダ自体を出さない', async () => {
    const calls: FetchCall[] = [];
    await pushAuthorizationRequest(baseRequest(stubFetchOk(VALID_PAR_BODY, calls)));
    // 空ヘッダを送ると AS が DPoP 利用の意図ありと解釈して形式不正で落としうる。
    expect(Object.hasOwn(calls[0]?.init.headers ?? {}, 'DPoP')).toBe(false);
  });

  it.each([
    ['空文字', ''],
    ['空白のみ', '   '],
  ])('dpop が%sなら 8010 で弾き fetch を呼ばない', async (_, dpop) => {
    const calls: FetchCall[] = [];
    const promise = pushAuthorizationRequest({
      ...baseRequest(stubFetchOk(VALID_PAR_BODY, calls)),
      dpop,
    });
    await expect(promise).rejects.toMatchObject({ code: ErrorCodes.TOKEN_REQUEST_FAILED });
    expect(calls).toHaveLength(0);
  });
});

describe('code_challenge の非空ガード（PKCE 必須）', () => {
  it.each([
    ['空文字', ''],
    ['空白のみ', '   '],
  ])('code_challenge が%sなら 8010 で弾き fetch を呼ばない', async (_, codeChallenge) => {
    const calls: FetchCall[] = [];
    const promise = pushAuthorizationRequest({
      ...baseRequest(stubFetchOk(VALID_PAR_BODY, calls)),
      code_challenge: codeChallenge,
    });
    await expect(promise).rejects.toMatchObject({ code: ErrorCodes.TOKEN_REQUEST_FAILED });
    // PKCE の結び付きが無い認可要求を AS へ届けない（push 前に落とす）。
    expect(calls).toHaveLength(0);
  });
});

describe('PARRequest.dpop の Object.prototype 汚染耐性', () => {
  const ATTACKER_PROOF = 'eyJ0eXAiOiJkcG9wK2p3dCJ9.attacker.sig';

  it('継承した dpop は DPoP ヘッダに載せない', async () => {
    const calls: FetchCall[] = [];
    // `dpop` を指定していない正当な push。鎖読みだと汚染値がヘッダに載って送出される。
    await withPollutedPrototypeAsync({ dpop: ATTACKER_PROOF }, () =>
      pushAuthorizationRequest(baseRequest(stubFetchOk(VALID_PAR_BODY, calls))),
    );
    expect(Object.hasOwn(calls[0]?.init.headers ?? {}, 'DPoP')).toBe(false);
  });

  it('汚染下でも明示的に渡した dpop はそのまま DPoP ヘッダに載る（正常系）', async () => {
    const calls: FetchCall[] = [];
    const proof = 'eyJ0eXAiOiJkcG9wK2p3dCJ9.legit.sig';
    await withPollutedPrototypeAsync({ dpop: ATTACKER_PROOF }, () =>
      pushAuthorizationRequest({
        ...baseRequest(stubFetchOk(VALID_PAR_BODY, calls)),
        dpop: proof,
      }),
    );
    expect(calls[0]?.init.headers.DPoP).toBe(proof);
  });
});
