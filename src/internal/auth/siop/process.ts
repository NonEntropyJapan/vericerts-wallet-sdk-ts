/**
 * DIDベース SIOPv2 Authorization Request の一括処理。
 *
 * `parseSIOPv2Request` → `assertValidRPRegistration` → `generateIDToken`（要求が `vp_token` も求めるなら
 * `generateVpToken` も）を順に実行し、`SIOPv2Response` を返す。`redirect_uri` への POST 送信は
 * `presentPseudonym` / `createPresentation` と同じ方針で上位層（wallet / extension）の責務とする。
 */

import type { CredentialSignerAlg } from '../../credential/vc/jws.js';
import type { AnyCredentialSigner } from '../../credential/vc/signer.js';
import type { FetchLike } from '../../fetch-di.js';
import { ownProperty } from '../../prototype-safety/own-property.js';
import { resolveClientMetadataUri } from './client-metadata-uri.js';
import { type GenerateIdTokenOptions, generateIDToken } from './id-token.js';
import { parseSIOPv2Request } from './parse.js';
import { assertValidRPRegistration } from './rp-registration.js';
import type { SIOPv2Response } from './types.js';
import { assertVpTokenRequestSupported, generateVpToken, requestsVpToken } from './vp-token.js';

/** `processSIOPv2Request` のオプション（ID Token 発行オプション + `client_metadata_uri` 取得用の fetch 差し替え）。 */
export interface ProcessSIOPv2Options extends GenerateIdTokenOptions {
  /** `client_metadata_uri` の取得に使う `fetch` 互換関数（テスト注入用。省略時はグローバル `fetch`）。 */
  readonly fetchImpl?: FetchLike;
}

/**
 * DID ベースの SIOPv2 Authorization Request を解析・検証し、ID Token と、要求時には VP Token を生成する。
 *
 * @param request `siopv2://?...` 形式の Authorization Request URI、または同じパラメータを持つ JSON オブジェクト。
 * @param did ID Token の `sub`（と VP Token の `holder`）に載せる Holder の DID。
 * @param signer DID の秘密鍵に対応する署名鍵。
 * @param opts ID Token 発行オプション（`nowSeconds` / `lifetimeSeconds`）と、`client_metadata_uri` 取得用の `fetchImpl`。
 * @returns 生成した ID Token を含む `SIOPv2Response`。`response_type` が `vp_token` を含むときは `vpToken` と `state` も返す。
 * @throws Request のパース失敗（code `4001`）、RP メタデータの検証失敗・`client_metadata_uri` の取得失敗（code `4002`）の場合。
 */
export async function processSIOPv2Request(
  request: string | Readonly<Record<string, unknown>>,
  did: string,
  signer: AnyCredentialSigner<CredentialSignerAlg>,
  opts: ProcessSIOPv2Options,
): Promise<SIOPv2Response> {
  const parsedRequest = parseSIOPv2Request(request);
  const wantsVpToken = requestsVpToken(parsedRequest.responseType);
  if (wantsVpToken) assertVpTokenRequestSupported(parsedRequest);
  // `client_metadata_uri` は承認後のここで初めて取得する（パース時点では通信しない）。
  const parsed = await resolveClientMetadataUri(parsedRequest, opts);
  assertValidRPRegistration(parsed, signer.alg);
  const idToken = await generateIDToken(parsed, did, signer, opts);
  if (!wantsVpToken) {
    return { idToken, redirectUri: parsed.redirectUri };
  }
  const vpToken = await generateVpToken(parsed, did, signer);
  // `state` は `vp_token` を要求する要求では必須（`assertVpTokenRequestSupported` で保証済み）。RP へそのまま返す。
  const state = ownProperty<string>(parsed, 'state');
  return { idToken, redirectUri: parsed.redirectUri, vpToken, state };
}
