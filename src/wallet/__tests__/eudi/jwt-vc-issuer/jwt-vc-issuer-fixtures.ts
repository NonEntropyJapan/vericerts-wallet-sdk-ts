/**
 * JWT VC Issuer Metadata 経路のテスト用フィクスチャ。
 *
 * 本経路の回帰テストは 2 ファイルに分かれる（`jwt-vc-issuer/wallet.eudi.receive-jwt-vc-issuer.test.ts` =
 * opt-in の境界、`jwt-vc-issuer/wallet.eudi.receive-jwt-vc-issuer-keys.test.ts` = 取得元 URL と鍵選択）。
 * 両者が同じ Issuer 構成・同じスタブ配線を使うため、組み立てをここへ集約する — 各ファイルに
 * 書き写すと、片方だけ metadata の形が更新されて「同じ経路のはずが別物を検証している」状態になる。
 *
 * ネットワークは `eudiFetchImpl` の注入のみで再現し、グローバル `fetch` は差し替えない
 * （`eudi-fixtures.ts` と同じ規律）。
 */

import type { FetchLike } from '../../../../internal/auth/oid4vci/oid4vci.js';
import { PID_VCT } from '../../../../internal/eudi/pid/index.js';
import type { WalletOptions } from '../../../options.js';
import type { Wallet } from '../../../types.js';
import {
  buildSdJwtVcWith,
  createStub,
  ISSUER,
  ISSUER_PUBLIC_JWK,
  jsonResponse,
  setupWallet,
  VALID_PID_CLAIMS,
} from '../eudi-fixtures.js';

/** JWT VC Issuer Metadata の well-known URL（`iss` がパスを持たない既定の Issuer）。 */
export const WELL_KNOWN_URL = `${ISSUER}/.well-known/jwt-vc-issuer`;

/** 同一 origin の JWK Set エンドポイント（`jwks_uri` 経路で使う）。 */
export const JWKS_URL = `${ISSUER}/keys/jwks.json`;

/** 別 origin の JWK Set エンドポイント（拒否されることを確かめる）。 */
export const FOREIGN_JWKS_URL = 'https://keys.attacker.example/jwks.json';

/** `ISSUER_PUBLIC_JWK` とは別の鍵（`kid` 選択の誤りを検出させるためのダミー）。 */
export const OTHER_JWK: Readonly<Record<string, unknown>> = {
  ...ISSUER_PUBLIC_JWK,
  x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
};

/**
 * リダイレクトを経た JSON 応答を返す（`Response.url` が最終 URL になった状態）。
 *
 * 実 `fetch` は追随後の最終 URL を `Response.url` に入れるが、`new Response(...)` の `url` は空文字
 * のままで代入もできない。SSRF 検査（最終 URL の origin 突合）を注入 `fetch` で再現するために
 * `url` を直接定義する。
 *
 * @param body JSON 本文。
 * @param finalUrl リダイレクト後の最終 URL。
 */
export function redirectedJsonResponse(
  body: Readonly<Record<string, unknown>>,
  finalUrl: string,
): Response {
  const response = jsonResponse(body);
  Object.defineProperty(response, 'url', { value: finalUrl, configurable: true });
  return response;
}

/** {@link metadataPidWallet} の入力（既定から外した部分だけを指定する）。 */
export interface Scenario {
  /** SD-JWT VC の `iss`（既定は `ISSUER`）。 */
  readonly iss?: string;
  /** Issuer-signed JWT ヘッダの `kid`。 */
  readonly kid?: string;
  /** 署名鍵の差し替え（偽 Issuer の再現）。 */
  readonly signingKey?: Uint8Array;
  /** well-known が返す metadata（既定は `issuer` + インライン `jwks`）。 */
  readonly metadata?: Readonly<Record<string, unknown>>;
  /**
   * well-known の応答そのものを差し替える（`metadata` より優先）。
   *
   * リダイレクト・Content-Type 不正など、**本文以外**を作り込む必要があるケース専用。
   */
  readonly wellKnownResponse?: () => Response;
  /** well-known 以外の追加ルート（`jwks_uri` の取得先など）。 */
  readonly routes?: Readonly<Record<string, () => Response>>;
  /** `createWallet` の追加オプション（既定は metadata 経路 opt-in）。 */
  readonly options?: Omit<WalletOptions, 'storage' | 'eudiFetchImpl'>;
}

/** {@link metadataPidWallet} の戻り値。 */
export interface MetadataPidWallet {
  /** 初期化済み Wallet。 */
  readonly wallet: Wallet;
  /** これまでに要求された URL（呼ばれた順）。 */
  readonly urls: () => readonly string[];
  /** 同じスタブ（`receiveCredential(offerURI, { fetchImpl })` へ渡す用）。 */
  readonly fetchImpl: FetchLike;
}

/** metadata 経路を使う Issuer の PID を返すスタブと、その Wallet を用意する。 */
export async function metadataPidWallet(scenario: Scenario = {}): Promise<MetadataPidWallet> {
  const iss = scenario.iss ?? ISSUER;
  const sdJwt = buildSdJwtVcWith({
    vct: PID_VCT,
    claims: VALID_PID_CLAIMS,
    iss,
    ...(scenario.kid === undefined ? {} : { kid: scenario.kid }),
    ...(scenario.signingKey === undefined ? {} : { signingKey: scenario.signingKey }),
  });
  const metadata = scenario.metadata ?? { issuer: iss, jwks: { keys: [ISSUER_PUBLIC_JWK] } };
  const stub = createStub(sdJwt, {
    ...scenario.routes,
    [WELL_KNOWN_URL]: scenario.wellKnownResponse ?? (() => jsonResponse(metadata)),
  });
  const wallet = await setupWallet({
    eudiFetchImpl: stub.fetchImpl,
    ...(scenario.options ?? { jwtVcIssuerMetadataResolution: true }),
  });
  return { wallet, urls: () => stub.calls.map((call) => call.url), fetchImpl: stub.fetchImpl };
}
