/**
 * JAR（JWT Authorization Request）JWT のクレーム展開。
 *
 * クエリパラメータ形式（`../request.ts` の `parseAuthorizationRequest`）と共通の構築ロジックは
 * `../request-common.ts` を参照（1 ファイル 300 行の Linterly 上限のため分離）。`jar/` 配下に
 * 置くのは、JAR 関連の他モジュール（`fetch-jar.ts` / `jar-signature.ts` 等）と同じ場所に集約する
 * ため（`auth/` 直下は 1 ディレクトリ 2000 行の Linterly 上限に達しているため新規ファイルを
 * 直下へは足さない）。`request.ts` が本モジュールの `parseJarRequest` を再エクスポートするため、
 * 既存の import パス（`from '../request.js'` / メインバレル）は変わらない。
 */

import { decodeCompactJws } from '../../credential/vc/jws.js';
import { ErrorCodes, VericertsError } from '../../errors.js';
import { ownProperty } from '../../prototype-safety/own-property.js';
import { type DcqlQuery, parseDcqlQuery } from '../dcql/dcql.js';
import { buildRequest, type PresentationRequest } from '../request-common.js';
import { parseTransactionDataClaim } from '../request-v2.js';

/** JAR クレームを JSON object として取り出す。非 object は 8030。未指定は `undefined`。 */
function asObjectClaim(value: unknown): Record<string, unknown> | undefined {
  if (value === undefined) {
    return undefined;
  }
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new VericertsError(ErrorCodes.OID4VP_REQUEST_PARSE_FAILED);
  }
  return value as Record<string, unknown>;
}

/**
 * JAR（JWT Authorization Request）JWT のクレームを `PresentationRequest` へ展開する。
 *
 * JAR は `request_uri` 参照形式で Verifier から取得した JWS（`application/oauth-authz-req+jwt`）。
 * 本関数は **取得済みの JAR JWT 文字列**（コンパクト JWS）を受け取り、ペイロードの OID4VP
 * パラメータを構造化する。`dcql_query` クレームは JSON object として埋め込まれている前提。
 *
 * **本関数は署名を検証しない。** 必須パラメータ検証と `response_uri` / `client_id` ドメイン整合性
 * チェックだけを行い、JWS 署名検証・`x5c` / Trust Anchor 検証・`iss == client_id`
 * 整合性確認は**行わない**。したがって戻り値は「**検証されていない**
 * Verifier の主張」であり、そのまま DCQL 評価や VP Token の送信先決定に使ってはならない
 * （`request_uri` は攻撃者が値を選べる URL であり、`client_id` と `response_uri` を攻撃者の
 * ドメインで揃えれば上記の検査はすべて通る）。取得も SDK に任せるなら `fetchJAR` /
 * `parsePresentationRequest`（どちらも解析前に `verifyJarSignature` を通す）を、取得を
 * 自前で行うなら本関数の前に `verifyJarSignature`（`@vericerts/vericerts-wallet-sdk/experimental`）を使う。
 *
 * @param jarJwt 取得済み JAR JWT（コンパクト JWS）。
 * @returns 正規化された `PresentationRequest`。
 * @throws 形式不正 / 必須パラメータ欠落 / DCQL 構文エラー時（VericertsError、code `8030`）。
 */
export function parseJarRequest(jarJwt: string): PresentationRequest {
  let payload: Record<string, unknown>;
  try {
    ({ payload } = decodeCompactJws(jarJwt));
  } catch {
    // 形式不正は 8030 へ正規化（JWT 本文は漏らさない）。
    throw new VericertsError(ErrorCodes.OID4VP_REQUEST_PARSE_FAILED);
  }

  // `payload` は `parseJsonWithoutPrototype` 由来だが、own 限定読みは多層防御で残す。鎖読みは
  // **`client_metadata` 無しの JAR でも汚染値が Verifier 告知として載り vp_token が奪われる**。
  const claim = (name: string): unknown => ownProperty<unknown>(payload, name);
  const dcqlClaim = claim('dcql_query');
  const pdClaim = claim('presentation_definition');

  let dcqlQuery: DcqlQuery | undefined;
  if (dcqlClaim !== undefined) {
    if (typeof dcqlClaim !== 'object' || dcqlClaim === null || Array.isArray(dcqlClaim)) {
      throw new VericertsError(ErrorCodes.OID4VP_REQUEST_PARSE_FAILED);
    }
    dcqlQuery = parseDcqlQuery(dcqlClaim as Record<string, unknown>);
  }

  const presentationDefinition = asObjectClaim(pdClaim);
  const clientMetadata = asObjectClaim(claim('client_metadata'));

  return buildRequest({
    responseType: claim('response_type'),
    clientId: claim('client_id'),
    responseMode: claim('response_mode'),
    responseUri: claim('response_uri'),
    nonce: claim('nonce'),
    state: claim('state'),
    dcqlQuery,
    presentationDefinition,
    clientMetadata,
    transactionData: parseTransactionDataClaim(claim('transaction_data')),
    requiredLoA: claim('required_loa'),
  });
}
