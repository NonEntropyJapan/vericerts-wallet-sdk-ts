/** OID4VP リクエストに応じて Wallet が提示を作成するための型。 */

import type { CreatedPresentation } from '../../internal/auth/create-presentation/index.js';
import type { MatchCredentialsOptions } from './match-api.js';

/**
 * `createPresentation` の戻り値型。`ReceivedVerifiableCredential`（`api.ts`）と同じ理由で、公開 API
 * から型名で参照できるようここで再エクスポートする。
 */
export type { CreatedPresentation };

/** Wallet の VP 作成 API。 */
export interface CreatePresentationApi {
  /**
   * OID4VP リクエストに応じて VP を作成し、JWT-VP として署名する。
   *
   * `issuePresentation` と異なり署名鍵を明示指定しない（アクティブペルソナから自動解決する。
   * `receiveCredential` / `presentPID` と同じパターン）。VC 選択そのものは `matchCredentials` /
   * `matchCredentialsByPresentationDefinition`が既に実装済みのロジックを再利用し、
   * `vcIDs` に挙げた VC が要求（`dcql_query` / `presentation_definition`）の候補集合に含まれることを
   * 検証する。複数 VC の組み合わせ要件（DCQL `credential_sets` / PEx v2
   * `submission_requirements`）の充足は呼び出し側が確認し、提示する VC を選ぶ。
   *
   * `verifiableCredential` には選択 VC を object（JSON-LD VC）表現のまま埋め込む。Wallet ローカル VC
   * ストアは構造化済み VC のみを保持し、受領時の署名済み JWT-VC 原本は保持しないためである。
   * JWT-VP の提示者署名は `verifyPresentation` で検証できる。JWT-VC の発行者署名を
   * `verifyCredential` で検証するには、元のコンパクト JWT が必要になる。
   *
   * LoA（Level of Assurance）判定: 要求が `required_loa` を告知している場合（解析結果の
   * `request.requiredLoA`）、選択 VC の**全件**に
   * `verifyEvidence` を適用し、1 件でも要求 LoA を満たさなければ `LOA_MISMATCH`
   * （code `10030`）で拒否する。`required_loa` の指定がなければ LoA 判定は行わない。
   *
   * 提示 VC のいずれかが `markCredentialDisputed` 済み（Art.16 訂正権フォールバック）の場合、戻り値の
   * `presentationMetadata.disputed` が `true` になる。UI 警告表示は呼び出し側
   * （extension 等）の責務。
   *
   * @param requestURI OID4VP Authorization Request URI（直接形式・`request_uri` 参照形式のどちらでもよい）。
   * @param vcIDs 提示する VC の ID 配列（`storeCredential` で永続化済みの `vc.id`）。
   * @param opts `request_uri` 参照形式でのみ使う Trust Anchor・HTTP 差し替えシーム（`matchCredentials`
   *             と同じ `MatchCredentialsOptions`）。
   * @returns 署名済み VP（`jwt` に JWT-VP、他メンバは VP 構造）。
   * @throws アクティブペルソナ未設定（code `2005`）、指定 VC が見つからない場合（`VC_NOT_FOUND`、
   *         code `3070`）、要求解析失敗（code `8030`。`request_uri` 参照形式では取得失敗・署名検証失敗・
   *         `opts.trustAnchors` 未指定を含む）、選択 VC が要求の候補集合に含まれない場合
   *         （`VC_REQUIREMENT_MISMATCH`、code `3080`）、`dcql_query` の要求 format が SDK 未対応の場合
   *         （`FORMAT_NEGOTIATION_FAILED`、code `8050`）、選択 VC のいずれかが要求の `required_loa` を
   *         満たさない場合（`LOA_MISMATCH`、code `10030`）の場合。
   *
   * @experimental 挙動・シグネチャが変わり得る。v1.0 で `@stable` に昇格予定。
   */
  createPresentation(
    requestURI: string,
    vcIDs: string[],
    opts?: MatchCredentialsOptions,
  ): Promise<CreatedPresentation>;
}
