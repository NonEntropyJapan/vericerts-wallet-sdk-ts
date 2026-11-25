/**
 * `transaction_data` の正規化と `PresentationRequestV2` 変換のユニットテスト（実鍵・モック禁止）。
 *
 * 検証内容:
 * - URL クエリ / JAR クレームの `transaction_data` が生 base64url 文字列のまま保持される。
 * - パース結果を `extractTransactionData` / `computeTransactionDataHashes` へ直接渡せる（型の接続）。
 * - `transaction_data` 未指定の後方互換（キー自体が生えない）。
 * - 配列でない / 空配列 / 非文字列要素 / 空文字列要素 / 不正 JSON は fail-closed で 8030。
 * - `toPresentationRequestV2` の 返却フィールドへの写像と `vp_formats` の null プロトタイプ化。
 * - `toVpFormats` の入力読み取りが own 限定であること（`Object.prototype` 汚染耐性）。
 */

import { describe, expect, it } from 'bun:test';
import { base64urlnopad } from '@scure/base';
import {
  withPollutedPrototype,
  withPollutedPrototypeAccessor,
} from '../../../__tests__/prototype-pollution.fixtures.js';
import { createSdJwt } from '../../../credential/sdjwt/sdjwt.js';
import { createPrivateKeySigner } from '../../../credential/vc/signer.js';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import {
  computeTransactionDataHashes,
  extractTransactionData,
} from '../../../eudi/transaction-data/index.js';
import type { PresentationRequest } from '../../request.js';
import { parseAuthorizationRequest, parseJarRequest } from '../../request.js';
import { PRESENTATION_REQUEST_V2_SPEC_VERSION, toPresentationRequestV2 } from '../../request-v2.js';

const CLIENT_ID = 'https://verifier.example.com';
const RESPONSE_URI = 'https://verifier.example.com/callback';
const NONCE = 'n-0S6_WzA2Mj-0123456789';
const STATE = 'af0ifjsldkj';

const DCQL = {
  credentials: [
    { id: 'pid', format: 'vc+sd-jwt', meta: { vct_values: ['https://example.com/pid'] } },
  ],
};

/** base64url エンコードされた Transaction Data 1 件を作る。 */
function encodeTxData(claims: Record<string, unknown>): string {
  return base64urlnopad.encode(new TextEncoder().encode(JSON.stringify(claims)));
}

const TX_PAYMENT = encodeTxData({
  type: 'urn:example:payment',
  credential_ids: ['pid'],
  amount: '42.00',
});
const TX_APPROVAL = encodeTxData({
  type: 'urn:example:approval',
  credential_ids: ['pid', 'approval'],
});

/** 正常系の URL クエリを組み立てる（request.test.ts と同じ形）。 */
function buildUri(overrides: Record<string, string | undefined> = {}): string {
  const params: Record<string, string | undefined> = {
    response_type: 'vp_token',
    client_id: CLIENT_ID,
    response_mode: 'direct_post',
    response_uri: RESPONSE_URI,
    nonce: NONCE,
    state: STATE,
    dcql_query: JSON.stringify(DCQL),
    ...overrides,
  };
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined) {
      search.set(key, value);
    }
  }
  return `openid4vp://?${search.toString()}`;
}

/** 8030 が投げられることを確認する。 */
function expect8030(run: () => unknown): void {
  try {
    run();
    throw new Error('should have thrown');
  } catch (err) {
    expect(err).toBeInstanceOf(VericertsError);
    expect((err as VericertsError).code).toBe(ErrorCodes.OID4VP_REQUEST_PARSE_FAILED);
  }
}

describe('transaction_data のパース（URL クエリ）', () => {
  it('生 base64url 文字列をそのまま保持する', () => {
    const req = parseAuthorizationRequest(
      buildUri({ transaction_data: JSON.stringify([TX_PAYMENT, TX_APPROVAL]) }),
    );
    expect(req.transactionData).toEqual([TX_PAYMENT, TX_APPROVAL]);
  });

  it('extractTransactionData へそのまま渡せる（型で接続されている）', () => {
    const req = parseAuthorizationRequest(
      buildUri({ transaction_data: JSON.stringify([TX_PAYMENT, TX_APPROVAL]) }),
    );
    const entries = extractTransactionData(req.transactionData);
    expect(entries.map((e) => e.type)).toEqual(['urn:example:payment', 'urn:example:approval']);
    expect(entries[0]?.credentialIds).toEqual(['pid']);
    expect(entries[1]?.credentialIds).toEqual(['pid', 'approval']);
    expect(entries.map((e) => e.encoded)).toEqual([TX_PAYMENT, TX_APPROVAL]);

    const hashes = computeTransactionDataHashes(entries);
    expect(hashes).toEqual(
      computeTransactionDataHashes(extractTransactionData([TX_PAYMENT, TX_APPROVAL])),
    );
  });

  it('transaction_data 未指定ならキー自体が生えない（後方互換）', () => {
    const req = parseAuthorizationRequest(buildUri());
    expect('transactionData' in req).toBe(false);
    expect(extractTransactionData(req.transactionData)).toEqual([]);
  });

  it('JSON object（配列でない）で 8030', () => {
    expect8030(() => parseAuthorizationRequest(buildUri({ transaction_data: '{"a":1}' })));
  });

  it('空配列で 8030（要求がないならパラメータを省略する）', () => {
    expect8030(() => parseAuthorizationRequest(buildUri({ transaction_data: '[]' })));
  });

  it('非文字列要素で 8030', () => {
    expect8030(() => parseAuthorizationRequest(buildUri({ transaction_data: '[1]' })));
  });

  it('空文字列要素で 8030', () => {
    expect8030(() => parseAuthorizationRequest(buildUri({ transaction_data: '[""]' })));
  });

  it('不正 JSON で 8030', () => {
    expect8030(() => parseAuthorizationRequest(buildUri({ transaction_data: '[not json' })));
  });
});

describe('transaction_data のパース（JAR）', () => {
  const JAR_KEY = new Uint8Array(32).fill(7);
  const signer = createPrivateKeySigner(JAR_KEY, 'ES256');

  /** OID4VP パラメータを payload に持つ JAR JWT を実署名で作る。 */
  function buildJarJwt(payload: Record<string, unknown>): string {
    const sdJwt = createSdJwt(signer, { vct: 'jar', disclosureClaims: [], claims: payload });
    return sdJwt.split('~')[0] as string;
  }

  const BASE_CLAIMS = {
    response_type: 'vp_token',
    client_id: CLIENT_ID,
    response_mode: 'direct_post',
    response_uri: RESPONSE_URI,
    nonce: NONCE,
    state: STATE,
  };

  it('JAR クレームの transaction_data を生 base64url 配列として展開する', () => {
    const req = parseJarRequest(buildJarJwt({ ...BASE_CLAIMS, transaction_data: [TX_PAYMENT] }));
    expect(req.transactionData).toEqual([TX_PAYMENT]);
    expect(extractTransactionData(req.transactionData)[0]?.type).toBe('urn:example:payment');
  });

  it('transaction_data クレーム未指定ならキー自体が生えない', () => {
    expect('transactionData' in parseJarRequest(buildJarJwt(BASE_CLAIMS))).toBe(false);
  });

  it('transaction_data クレームが配列でないと 8030', () => {
    expect8030(() => parseJarRequest(buildJarJwt({ ...BASE_CLAIMS, transaction_data: {} })));
  });

  it('transaction_data クレームが空配列で 8030', () => {
    expect8030(() => parseJarRequest(buildJarJwt({ ...BASE_CLAIMS, transaction_data: [] })));
  });
});

describe('toPresentationRequestV2', () => {
  const VP_FORMATS = { 'dc+sd-jwt': { alg: ['ES256'] } };

  it('PresentationRequestV2 の各フィールドへ写像する', () => {
    const req = parseAuthorizationRequest(
      buildUri({
        transaction_data: JSON.stringify([TX_PAYMENT]),
        client_metadata: JSON.stringify({ vp_formats: VP_FORMATS }),
      }),
    );
    const v2 = toPresentationRequestV2(req);
    expect(v2.id).toBe(STATE);
    expect(v2.challenge).toBe(NONCE);
    expect(v2.domain).toBe(CLIENT_ID);
    expect(v2.spec_version).toBe(PRESENTATION_REQUEST_V2_SPEC_VERSION);
    expect(v2.dcql_query?.credentials[0]?.id).toBe('pid');
    expect(v2.transaction_data).toEqual([TX_PAYMENT]);
    expect(v2.vp_formats['dc+sd-jwt']).toEqual({ alg: ['ES256'] });
    expect(v2.request_uri).toBeUndefined();
    expect(v2.request).toBeUndefined();
  });

  it('presentation_definition は生 JSON のまま載せ、未指定の任意フィールドは省略する', () => {
    const pd = { id: 'pd-1', input_descriptors: [] };
    const v2 = toPresentationRequestV2(
      parseAuthorizationRequest(
        buildUri({ dcql_query: undefined, presentation_definition: JSON.stringify(pd) }),
      ),
    );
    expect(v2.presentation_definition).toEqual(pd);
    expect('dcql_query' in v2).toBe(false);
    expect('transaction_data' in v2).toBe(false);
  });

  it('client_metadata 未指定なら vp_formats は空の要求表になる', () => {
    const v2 = toPresentationRequestV2(parseAuthorizationRequest(buildUri()));
    expect(Object.keys(v2.vp_formats)).toEqual([]);
  });

  it('vp_formats は null プロトタイプで、未宣言の constructor 等が引けない', () => {
    const v2 = toPresentationRequestV2(
      parseAuthorizationRequest(
        buildUri({ client_metadata: JSON.stringify({ vp_formats: VP_FORMATS }) }),
      ),
    );
    expect(Object.getPrototypeOf(v2.vp_formats)).toBeNull();
    expect((v2.vp_formats as Record<string, unknown>).constructor).toBeUndefined();
    expect((v2.vp_formats as Record<string, unknown>).toString).toBeUndefined();
  });
});

describe('toVpFormats の own 限定読み取り（Object.prototype 汚染耐性）', () => {
  const ATTACKER_FORMATS = { 'attacker+format': { alg: ['none'] } };
  const HONEST_FORMATS = { 'dc+sd-jwt': { alg: ['ES256'] } };

  /**
   * 呼び出し側が `parseAuthorizationRequest` / `parseJarRequest` を経由せず自前で組み立てる
   * `PresentationRequest`。`clientMetadata` は通常のオブジェクトリテラル
   * （`parseJsonWithoutPrototype` を経由しないため `Object.prototype` を継承する）。
   */
  function requestWithClientMetadata(
    clientMetadata?: Record<string, unknown>,
  ): PresentationRequest {
    return {
      responseType: 'vp_token',
      clientId: CLIENT_ID,
      responseMode: 'direct_post',
      responseUri: RESPONSE_URI,
      nonce: NONCE,
      state: STATE,
      ...(clientMetadata !== undefined ? { clientMetadata } : {}),
    };
  }

  it('client_metadata が vp_formats を持たなければ、Object.prototype のデータ汚染を拾わず空の要求表になる', () => {
    const v2 = withPollutedPrototype({ vp_formats: ATTACKER_FORMATS }, () =>
      toPresentationRequestV2(requestWithClientMetadata({ some_other_field: true })),
    );
    expect(v2.vp_formats).toEqual({});
  });

  it('client_metadata 自体が未指定でも、Object.prototype のデータ汚染を拾わず空の要求表になる', () => {
    const v2 = withPollutedPrototype({ vp_formats: ATTACKER_FORMATS }, () =>
      toPresentationRequestV2(requestWithClientMetadata(undefined)),
    );
    expect(v2.vp_formats).toEqual({});
  });

  it('client_metadata が vp_formats を持たなければ、Object.prototype のアクセサ汚染も拾わず空の要求表になる', () => {
    const v2 = withPollutedPrototypeAccessor({ vp_formats: () => ATTACKER_FORMATS }, () =>
      toPresentationRequestV2(requestWithClientMetadata({})),
    );
    expect(v2.vp_formats).toEqual({});
  });

  it('client_metadata が own の vp_formats を持つ場合は、汚染下でも own の値をそのまま採用する', () => {
    const v2 = withPollutedPrototype({ vp_formats: ATTACKER_FORMATS }, () =>
      toPresentationRequestV2(requestWithClientMetadata({ vp_formats: HONEST_FORMATS })),
    );
    expect(v2.vp_formats).toEqual(HONEST_FORMATS);
  });
});

describe('公開バレル（exports/auth.ts）からの到達性', () => {
  it('PresentationRequestV2 関連の名前が公開されている', async () => {
    const auth = await import('../../../../exports/auth.js');
    expect(auth.PRESENTATION_REQUEST_V2_SPEC_VERSION).toBe(PRESENTATION_REQUEST_V2_SPEC_VERSION);
    expect(typeof auth.toPresentationRequestV2).toBe('function');
    expect(typeof auth.parseTransactionDataClaim).toBe('function');
    expect(typeof auth.parseTransactionDataQueryParam).toBe('function');
    expect(auth.parseTransactionDataQueryParam(JSON.stringify([TX_PAYMENT]))).toEqual([TX_PAYMENT]);
    expect(auth.parseTransactionDataClaim(undefined)).toBeUndefined();
  });
});
