/**
 * `client_metadata_uri` の取得（SIOPv2 §7.2 / OID4VP §5.1）。
 *
 * RP は `client_metadata` を要求に埋め込む代わりに、メタデータ文書の URL（`client_metadata_uri`）を載せられる。
 * 取得先は攻撃者が選べる QR / Deep Link 由来なので、`parseSIOPv2Request` が公開 HTTPS URL であることを確かめた
 * うえで、承認後の `processSIOPv2Request` から本関数で取得する（承認前は通信しない）。取得そのものは
 * 横断プリミティブ `http/fetch-json.ts`（公開 HTTPS へ縛ったリダイレクト追従・タイムアウト・本文上限・JSON object 判定）
 * を使い、検査を書き写さない。
 *
 * セキュリティ上の注意: 例外の `context` には固定の理由だけを載せ、URL・本文を含めない。
 */

import { ErrorCodes, VericertsError } from '../../errors.js';
import { type FetchLike, resolveInjectedFetch } from '../../fetch-di.js';
import { fetchJsonWithinLimits, type JsonFetchReason } from '../../http/fetch-json.js';
import { ownProperty } from '../../prototype-safety/own-property.js';
import { parseFetchedClientMetadata } from './rp-metadata.js';
import type { SIOPv2Request } from './types.js';

/**
 * 要求が `client_metadata_uri` を持つなら、その文書を取得して `clientMetadata` として載せた要求を返す。
 * 持たなければ要求をそのまま返す。
 *
 * @param request パース済み `SIOPv2Request`。
 * @param deps `fetchImpl`（HTTP 呼び出しの差し替えシーム。省略時はグローバル `fetch`）の注入。
 * @throws 取得に失敗した場合（VericertsError、code `4002`。`context.reason` は `client_metadata_uri_` + 失敗理由）、
 *   文書の形が不正な場合（code `4001`）。
 */
export async function resolveClientMetadataUri(
  request: SIOPv2Request,
  deps: { readonly fetchImpl?: FetchLike },
): Promise<SIOPv2Request> {
  // own 限定（未提示の要求が `Object.prototype.clientMetadataUri` の汚染値で取得先を握られない）。
  const uri = ownProperty<string>(request, 'clientMetadataUri');
  if (uri === undefined) return request;
  // `fetchImpl` は DI 依存なので `resolveInjectedFetch` で読み（`Object.prototype.fetchImpl` の汚染値を採用しない）、
  // レシーバはここで束ねる（グローバル `fetch` には束ねない。`credential/json-schema/fetch-document.ts` と同じ）。
  const { doFetch, receiver } = resolveInjectedFetch(deps);
  const fetchImpl: FetchLike = receiver === undefined ? doFetch : doFetch.bind(receiver);
  const document = await fetchJsonWithinLimits(
    uri,
    fetchImpl,
    (reason: JsonFetchReason) =>
      new VericertsError(ErrorCodes.RP_REGISTRATION_INVALID, {
        context: { reason: `client_metadata_uri_${reason}` },
      }),
  );
  return { ...request, clientMetadata: parseFetchedClientMetadata(document) };
}
