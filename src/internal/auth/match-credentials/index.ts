/**
 * OID4VP Presentation Request に合致する保有 VC を選定する。
 *
 * 直接形式・`request_uri` 参照形式（JAR）の解析には `parsePresentationRequest` を使う。
 * `dcql_query` は DCQL 要件に一致する VC のインデックスを求める。
 * `presentation_definition` は DIF Presentation Exchange v2 として構造を検査してから評価し、
 * 不正な構造は `8030` で拒否する。例外や `context` に VC 本文・クレーム値・Request 本文を含めない。
 */

import type { VerifiableCredential } from '../../credential/index.js';
import { ownProperty } from '../../prototype-safety/own-property.js';
import type { DcqlQuery } from '../dcql/dcql.js';
import { findMatchingCredentialIndexes } from '../dcql/dcql.js';
import type { PresentationRequestOptions } from '../jar/index.js';
import { parsePresentationRequest } from '../jar/index.js';
import { toQueryableFromVc } from '../matcher.js';
import type { PresentationRequest } from '../request.js';

/**
 * 解析済みの Presentation Request に対して VC 候補を選定する。
 *
 * `matchCredentials`（要求解析込み）と `createPresentation`が
 * 共有する。後者は `parsePresentationRequest`（`request_uri` 参照形式では HTTP 取得 + JAR 署名検証を
 * 伴う）を VP の `audience` / `nonce` 抽出にも使うため、解析済みの `request` を受け取る本関数へ分離
 * することで要求解析を 1 回に抑える（2 回解析すると通信・暗号検証が二重に走る）。
 *
 * @param request 解析済みの Presentation Request。
 * @param heldCredentials マッチ対象の保有 VC。呼び出し側が処理制限中（`processingRestricted`）の VC を
 *                        除外済みであること。
 * @returns 合致した VC（`request` が `dcql_query` / `presentation_definition` のいずれも持たない場合は
 *          空配列）。
 * @throws `presentation_definition` の構造不正（code `8030`）、`dcql_query` の要求 format が SDK
 *         未対応の場合（`FORMAT_NEGOTIATION_FAILED`、code `8050`）（VericertsError）。
 */
export async function matchCredentialsAgainstRequest(
  request: PresentationRequest,
  heldCredentials: readonly VerifiableCredential[],
): Promise<VerifiableCredential[]> {
  // `request.dcqlQuery` / `request.presentationDefinition` を own 限定で読む（`ownProperty`）。
  // `buildRequest`（request.ts）は未指定のクエリキーを条件付き展開で生やさないため、両方とも
  // 持たない要求では own プロパティとして存在しない。鎖読み（`request.dcqlQuery !== undefined` 等）
  // だと `Object.prototype` 汚染下でそれを「未指定」と区別できず、本来 3080 で拒否されるべき要求が
  // 汚染された `dcqlQuery` / `presentationDefinition` を使って候補集合を（誤って）持ってしまう。
  // この候補集合は UI 表示と開示制御の両方に使う。
  const dcqlQuery = ownProperty<DcqlQuery>(request, 'dcqlQuery');
  if (dcqlQuery !== undefined) {
    // format ラベルは既定（`jwt_vc_json`）のまま渡す。ウォレット保管層が VC ごとの format ヒントを
    // 保持していない現状、この層に `jwt_vc_json-ld` を選ぶ根拠が無いためである（VC 本文からは
    // 区別できない。`matcher.ts` の JSDoc 参照）。保管層が format を持つようになれば、その値を
    // `toQueryableFromVc` の第 2 引数へ通す別 Issue で解消する。
    const queryables = heldCredentials.map((vc) => toQueryableFromVc(vc));
    const matchedIndexes = findMatchingCredentialIndexes(dcqlQuery, queryables);
    return matchedIndexes.map((index) => heldCredentials[index] as VerifiableCredential);
  }

  const presentationDefinition = ownProperty<Readonly<Record<string, unknown>>>(
    request,
    'presentationDefinition',
  );
  if (presentationDefinition !== undefined) {
    // PEx v2 の評価エンジン（`presentation-exchange/evaluate.ts`）は `jsonpath-plus` を引く。
    // 静的 import にすると、`dcql_query` しか扱わない利用者（extension の did_presentVP は
    // `presentation_definition` を 8030 で拒否する）のバンドルにも評価エンジンと jsonpath-plus が
    // そのまま載る。要求が実際に `presentation_definition` を持つときにだけ読み込む。
    const { matchCredentialsByPresentationDefinitionJson } = await import(
      '../match-by-presentation-definition.js'
    );
    return matchCredentialsByPresentationDefinitionJson(presentationDefinition, heldCredentials);
  }

  return [];
}

/**
 * Presentation Request に合致する VC 候補を返す。
 *
 * @param requestURI OID4VP Authorization Request URI（直接形式・`request_uri` 参照形式のどちらでもよい）。
 * @param heldCredentials マッチ対象の保有 VC。呼び出し側が処理制限中（`processingRestricted`）の VC を
 *                        除外済みであること。
 * @param opts `request_uri` 参照形式でのみ使う Trust Anchor・HTTP 差し替えシーム。
 * @returns 合致した VC（要求が `dcql_query` / `presentation_definition` のいずれも持たない場合は
 *          空配列）。
 * @throws 要求解析失敗・`presentation_definition` の構造不正（いずれも code `8030`。`request_uri`
 *         参照形式では取得失敗・署名検証失敗・`opts.trustAnchors` 未指定を含む）、`dcql_query` の
 *         要求 format が SDK 未対応の場合（`FORMAT_NEGOTIATION_FAILED`、code `8050`）（VericertsError）。
 */
export async function matchCredentials(
  requestURI: string,
  heldCredentials: readonly VerifiableCredential[],
  opts?: PresentationRequestOptions,
): Promise<VerifiableCredential[]> {
  const request = await parsePresentationRequest(requestURI, opts);
  return await matchCredentialsAgainstRequest(request, heldCredentials);
}
