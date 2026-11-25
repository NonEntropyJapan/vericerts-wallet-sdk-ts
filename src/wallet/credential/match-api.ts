/** Wallet が提示要求に合致する VC を選定するための型。 */

import type { PresentationRequestOptions } from '../../internal/auth/index.js';
import type { VerifiableCredential } from '../../internal/credential/index.js';
import type { PresentationDefinition } from '../../internal/presentation-exchange/index.js';

/** `Wallet.matchCredentials` が `request_uri` の取得・署名検証に使うオプション。 */
export type MatchCredentialsOptions = PresentationRequestOptions;

/** 提示要求から保有 VC の候補を選ぶ API。 */
export interface MatchApi {
  /**
   * Presentation Request に合致する保有 VC の候補を返す。GDPR Art.18 に基づき処理を制限した VC は除外する。
   * `dcql_query` は DCQL の条件で、`presentation_definition` は
   * `matchCredentialsByPresentationDefinition` と同じ条件で評価する。
   *
   * @param requestURI OID4VP Authorization Request URI（直接形式・`request_uri` 参照形式どちらも可）。
   * @param opts `request_uri` 参照形式でのみ使う Trust Anchor・HTTP 差し替えシーム。
   * @returns 合致した VC（いずれの形式も持たない要求では空配列）。
   * @throws 要求解析失敗・`presentation_definition` 構造不正（`8030`）、DCQL format 未対応
   *         （`8050`）、保持 VC の復号失敗（`3070`）の場合。
   *
   * @experimental 公開直後は挙動・シグネチャが変わり得る。
   */
  matchCredentials(
    requestURI: string,
    opts?: MatchCredentialsOptions,
  ): Promise<VerifiableCredential[]>;

  /**
   * DIF Presentation Exchange v2 の PresentationDefinition に合致する保有 VC を返す。
   * GDPR Art.18 に基づき処理を制限した VC は除外する。
   * いずれかの input descriptor の `format` と `constraints.fields` を満たす VC を候補に含める。
   * 複数の記述子に合致した VC は一度だけ返す。提示する VC は呼び出し側が選ぶ。
   * 対象は W3C VerifiableCredential のみ（SD-JWT VC は対象外）。
   *
   * @param pd 評価対象の Presentation Definition（`parsePresentationDefinition` でパース済み）。
   * @returns マッチした VC（保持順、重複なし）。
   * @throws storage 上のデータ破損で復号に失敗した場合（VericertsError、code `3070`）。
   */
  matchCredentialsByPresentationDefinition(
    pd: PresentationDefinition,
  ): Promise<VerifiableCredential[]>;
}
