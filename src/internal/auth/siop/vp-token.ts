/**
 * DIDベース SIOPv2 の VP Token 生成。
 *
 * `response_type` が `vp_token` を含む要求（vericerts-anchor のログイン）では、ID Token と一緒に、同じ DID が
 * `holder` として署名した VC を含まない VP（`typ=vp+jwt`）を返す。`dcql_query` / `presentation_definition`
 * は評価しない（VC を見せるログインは対象外）ので、それらを含む要求は `assertVpTokenRequestSupported` が拒否する。
 */

import { issueVpJwtAsync } from '../../credential/presentation/issue-vp-jwt.js';
import type { CredentialSignerAlg } from '../../credential/vc/jws.js';
import type { AnyCredentialSigner } from '../../credential/vc/signer.js';
import { ErrorCodes, VericertsError } from '../../errors.js';
import { ownProperty } from '../../prototype-safety/own-property.js';
import type { SIOPv2Request } from './types.js';

/** `response_type` のうち VP Token を要求するトークン。 */
const VP_TOKEN_RESPONSE_TYPE_TOKEN = 'vp_token';

/** `vp_token` を要求する場合に対応するレスポンスモード。 */
const SUPPORTED_RESPONSE_MODE = 'direct_post';
/** `vp_token` を要求する場合に対応する ID Token 種別（Wallet は自己署名の ID Token だけを作る）。 */
const SUBJECT_SIGNED_ID_TOKEN_TYPE = 'subject_signed_id_token';

/** 要求が VP Token も求めているか（`response_type` が `vp_token` を含む）。 */
export function requestsVpToken(responseType: string): boolean {
  return responseType.split(' ').includes(VP_TOKEN_RESPONSE_TYPE_TOKEN);
}

/**
 * 要求に応える VC なしの VP Token を生成する（`typ=vp+jwt`）。
 *
 * `holder` は ID Token の `iss` / `sub` と同じ DID、`aud` は要求の `client_id`、`nonce` は要求の `nonce`。
 * RP は両トークンを同じ DID・nonce・audience に結びつけて検証する。
 *
 * @param request パース済み・RP メタデータを検証済みの `SIOPv2Request`。
 * @param did VP の `holder` に載せる Holder の DID（ID Token の `sub` と同じ値を渡すこと）。
 * @param signer DID の秘密鍵に対応する署名鍵。
 * @returns 署名済みコンパクト JWS（VP Token）。
 */
export function generateVpToken(
  request: SIOPv2Request,
  did: string,
  signer: AnyCredentialSigner<CredentialSignerAlg>,
): Promise<string> {
  return issueVpJwtAsync(did, signer, { audience: request.clientId, nonce: request.nonce });
}

/**
 * `vp_token` を要求する Authorization Request を Wallet が返せる形か確かめる。`direct_post` で `state` つき、自己署名の
 * ID Token で、VC を求める問い合わせ（`dcql_query` 等）を含まないものでなければ拒否する（`response_mode` の省略は OID4VP の既定が fragment なので認めず、明示を求める）。
 * `vp_token` を要求しない（`id_token` のみ）旧来の要求には何も足さない。
 *
 * @throws `state` が無い・`response_mode` が `direct_post` でない・`id_token_type` が `subject_signed_id_token` を
 *   含まない・VC を求める問い合わせ（`dcql_query` / `presentation_definition` / `presentation_definition_uri` / `claims`）を
 *   含む場合（VC なしの VP を返すと、VC を求めた RP に黙って別物を渡すことになるため）（VericertsError、code `4001`）。
 */
export function assertVpTokenRequestSupported(request: SIOPv2Request): void {
  const fail = (reason: string) =>
    new VericertsError(ErrorCodes.SIOPV2_REQUEST_PARSE_FAILED, { context: { reason } });
  if (ownProperty<string>(request, 'state') === undefined) throw fail('state_required');
  if (ownProperty<string>(request, 'responseMode') !== SUPPORTED_RESPONSE_MODE) {
    throw fail('response_mode_unsupported');
  }
  if (ownProperty<boolean>(request, 'requestsCredentials') === true) {
    throw fail('credential_query_unsupported');
  }
  const idTokenType = ownProperty<string>(request, 'idTokenType');
  if (idTokenType !== undefined && !idTokenType.split(' ').includes(SUBJECT_SIGNED_ID_TOKEN_TYPE)) {
    throw fail('id_token_type_unsupported');
  }
}
