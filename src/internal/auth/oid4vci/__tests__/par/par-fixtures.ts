/**
 * OID4VCI PAR のテスト共有フィクスチャ。
 *
 * `oid4vci/par/par.ts`（push）と `oid4vci-authz-url.ts`（認可 URL 構築）は
 * 責務ごとにモジュール分割したが、認可 URL 構築のエンドツーエンド検証は PAR 応答の
 * `request_uri` を入力に取るため、双方のテストが同じ fetch スタブと基本リクエストを必要とする。
 * 片方だけスタブの挙動が変わると経路間の整合が崩れるため、1 か所に集約する。
 */

import { WUA_CLIENT_ASSERTION_TYPE } from '../../../../eudi/wua/types.js';
import type { FetchLike } from '../../oid4vci.js';
import type { PARRequest } from '../../par/index.js';

/** テスト用の PAR エンドポイント（HTTPS 必須）。 */
export const PAR_ENDPOINT = 'https://issuer.example.com/par';

/** テスト用の Authorization Endpoint（HTTPS 必須）。 */
export const AUTHORIZATION_ENDPOINT = 'https://issuer.example.com/authorize';

/** AS が返す正常な PAR 応答（RFC 9126 §2.2）。 */
export const VALID_PAR_BODY = {
  request_uri: 'urn:ietf:params:oauth:request_uri:6esc_11ACC5bwc014ltc14eY22c',
  expires_in: 60,
} as const;

/** 128-bit 以上の乱数を base64url 化した想定の state。 */
export const STATE = 'Zm9vYmFyLXN0YXRlLTEyOGJpdA';

/**
 * PAR 経路のクライアント認証方式。`client_assertion_type` に使う URN を
 * 既存の公開定数 `WUA_CLIENT_ASSERTION_TYPE` から取り、
 * テスト側でリテラルを二重定義しない。
 */
export const WALLET_ATTESTATION_ASSERTION_TYPE = WUA_CLIENT_ASSERTION_TYPE;

/**
 * PAR 経路に載せる `client_assertion` のサンプル値。
 * `<WUA>~<WUA-PoP>`（WUA JWT と WUA-PoP JWT を
 * `~` で連結した形）に一致させる。PAR 経路と Token Request 経路で形式の使い分けはしない。
 */
export const WALLET_ATTESTATION_CLIENT_ASSERTION = 'eyJ.wua.jwt~eyJ.wua.pop';

/** fetch スタブが記録する 1 回分の呼び出し（ヘッダ検証のため init ごと保持する）。 */
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

/** 必須フィールドのみを埋めた PAR リクエスト。 */
export function baseRequest(fetchImpl: FetchLike): PARRequest {
  return {
    par_endpoint: PAR_ENDPOINT,
    client_id: 'wallet-client',
    code_challenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
    redirect_uri: 'com.example.wallet://cb',
    state: STATE,
    fetchImpl,
  };
}
