/**
 * OID4VP 経路の PAR のテスト共有フィクスチャ。
 *
 * `oid4vci/__tests__/par/par-fixtures.ts` と同じ形の最小フィクスチャ集約。2 経路は型を共有しない
 *ため、フィクスチャも別ファイルに持つ。
 */

import { WUA_CLIENT_ASSERTION_TYPE } from '../../../eudi/wua/types.js';
import type { FetchLike } from '../../../fetch-di.js';
import type { OID4VPPARRequest } from '../par.js';

/** テスト用の PAR エンドポイント（Verifier、HTTPS 必須）。 */
export const PAR_ENDPOINT = 'https://verifier.example.com/par';

/** Verifier が返す正常な PAR 応答（RFC 9126 §2.2）。 */
export const VALID_PAR_BODY = {
  request_uri: 'urn:ietf:params:oauth:request_uri:6esc_11ACC5bwc014ltc14eY22c',
  expires_in: 60,
} as const;

/** 128-bit 以上の乱数を base64url 化した想定の state。 */
export const STATE = 'Zm9vYmFyLXN0YXRlLTEyOGJpdA';

/** OID4VP の nonce。提示要求の必須フィールド。 */
export const NONCE = 'n-0S6_WzA2Mj';

/** クライアント認証方式。OID4VCI と同じ公開定数を使い、リテラルを二重定義しない。 */
export const WALLET_ATTESTATION_ASSERTION_TYPE = WUA_CLIENT_ASSERTION_TYPE;

/** `client_assertion` のサンプル値（`<WUA>~<WUA-PoP>`）。 */
export const WALLET_ATTESTATION_CLIENT_ASSERTION = 'eyJ.wua.jwt~eyJ.wua.pop';

/** fetch スタブが記録する 1 回分の呼び出し。 */
export interface FetchCall {
  readonly url: string;
  readonly init: { method: string; headers: Record<string, string>; body: string };
  readonly body: URLSearchParams;
}

/** 成功レスポンスを返す fetch スタブ。呼び出し内容を `calls` に記録する。 */
export function stubFetchOk(body: unknown, calls: FetchCall[], status = 201): FetchLike {
  return async (url, init) => {
    calls.push({ url, init, body: new URLSearchParams(init.body) });
    return new Response(JSON.stringify(body), {
      status,
      headers: { 'Content-Type': 'application/json' },
    });
  };
}

/** 任意のレスポンス（生の本文・ステータス）を返す fetch スタブ。 */
export function stubFetchRaw(responseBody: string, status: number): FetchLike {
  return async () =>
    new Response(responseBody, { status, headers: { 'Content-Type': 'application/json' } });
}

/** 必須フィールドのみを埋めた OID4VP PAR リクエスト。 */
export function baseRequest(fetchImpl: FetchLike): OID4VPPARRequest {
  return {
    par_endpoint: PAR_ENDPOINT,
    client_id: 'wallet-client',
    code_challenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
    state: STATE,
    nonce: NONCE,
    fetchImpl,
  };
}
