/**
 * `obtainWalletUnitAttestation` の 2 段取得フローテスト用の
 * HTTP スタブと共通オプション。
 *
 * ネットワークは**グローバル `fetch` を差し替えず** `fetchImpl` の注入だけで再現し、要求 URL と
 * 本文を記録して「どちらの段まで進んだか」「何を送ったか」を直接主張できるようにする。
 * 正常系（`obtain.test.ts`）と失敗経路（`obtain.failures.test.ts`）の両方から使う。
 */

import { expect } from 'bun:test';
import type { FetchLike } from '../../../auth/oid4vci/oid4vci.js';
import { VericertsError } from '../../../errors.js';
import type { ObtainWalletAttestationOptions } from '../obtain.js';
import { toP256Jwk, WSCD_PRIVATE_KEY, wscdSigner } from './wua-fixtures.js';

/** Wallet Provider（WUA 署名者）の秘密鍵と、信頼済みとして呼び出し側が渡す公開鍵 JWK。 */
export const PROVIDER_KEY = new Uint8Array(32).fill(3);
export const PROVIDER_JWK = toP256Jwk(PROVIDER_KEY);

/** 検証時刻（`makeWuaJwt` 既定の `iat` < NOW < `exp`）。 */
export const NOW = 1_712_400_000;

/** Wallet Provider Backend のベース URL（HTTPS）。 */
export const ENDPOINT = 'https://wallet-provider.example.eu/wallet-unit-attestation';

/** 2 段フローの各要求 URL（`ENDPOINT` の末尾スラッシュを除去して固定パスを連結したもの）。 */
export const CHALLENGE_URL = `${ENDPOINT}/wua/challenge`;
export const ISSUE_URL = `${ENDPOINT}/wua/issue`;

/** `/wua/challenge` が返す既定の challenge / nonce。 */
export const CHALLENGE = 'Y2hhbGxlbmdl';
export const NONCE = 'bm9uY2U';

/** 記録された 1 要求（URL と送信本文）。 */
export interface RecordedRequest {
  /** 要求 URL。 */
  readonly url: string;
  /** 送信した JSON 本文。 */
  readonly body: string;
}

/** URL と本文を記録するスタブ fetch と、その記録。 */
export interface StubFetch {
  /** 記録された要求（呼ばれた順）。空配列 = 一度も通信していない。 */
  readonly requests: RecordedRequest[];
  /** `fetchImpl` として注入する実装。 */
  readonly fetchImpl: FetchLike;
}

/** URL ごとに応答を決める関数からスタブ fetch を作る。 */
export function stubFetch(respond: (url: string) => Response | Promise<Response>): StubFetch {
  const requests: RecordedRequest[] = [];
  const fetchImpl: FetchLike = (url, init) => {
    requests.push({ url, body: init.body });
    return Promise.resolve(respond(url));
  };
  return { requests, fetchImpl };
}

/** JSON 本文の 200 応答。 */
export function jsonResponse(body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  });
}

/**
 * 2 段フローを最後まで通すスタブ fetch を作る。
 *
 * @param jwt `/wua/issue` が返す WUA JWT。
 * @param challengeBody `/wua/challenge` の応答本文（既定は `wp_policy` 付きの正常応答）。
 */
export function stubTwoStage(
  jwt: string,
  challengeBody: unknown = { challenge: CHALLENGE, nonce: NONCE, wp_policy: { min_os: '14' } },
): StubFetch {
  return stubFetch((url) =>
    url === CHALLENGE_URL ? jsonResponse(challengeBody) : jsonResponse({ wallet_attestation: jwt }),
  );
}

/** 既定の取得オプション（WSCD 鍵で署名し、信頼済み Provider 鍵で検証する）。 */
export function obtainOptions(
  stub: StubFetch,
  extra: Partial<ObtainWalletAttestationOptions> = {},
): ObtainWalletAttestationOptions {
  return {
    providerJwk: PROVIDER_JWK,
    signer: wscdSigner(),
    nowSeconds: NOW,
    fetchImpl: stub.fetchImpl,
    ...extra,
  };
}

/** WSCD 公開鍵 JWK（`makeWuaJwt` 既定の `cnf.jwk` と同じ鍵）。 */
export function wscdJwk(): ReturnType<typeof toP256Jwk> {
  return toP256Jwk(WSCD_PRIVATE_KEY);
}

/** 投げられた VericertsError のコードを取り出す（投げなければ失敗させる）。 */
export async function codeOf(run: () => Promise<unknown>): Promise<string> {
  try {
    await run();
  } catch (e) {
    expect(e).toBeInstanceOf(VericertsError);
    return (e as VericertsError).code;
  }
  throw new Error('should throw');
}
