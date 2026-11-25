/**
 * `IssuerModule.issueVC` の VC 本体組み立て（`IssueOptions` → `VerifiableCredential` の写像）。
 *
 * `issuer-module.ts` からビットインデックス管理と分離し、「オプションのどのフィールドが VC の
 * どのフィールドになるか」を 1 箇所に集約する。署名・シリアライズは行わない（低レベル
 * プリミティブ `issueCredential` / `createSdJwt` の責務）。
 *
 * セキュリティ上の注意:
 * - 例外メッセージや `context` に DID・クレームを含めない。
 */

import { VC_TYPE, VC_V2_CONTEXT } from '../../credential/presentation/vp.js';
import type { StatusReference } from '../../credential/sdjwt/sdjwt.js';
import type { VerifiableCredential } from '../../credential/vc/vc.js';
import { ownProperty } from '../../prototype-safety/own-property.js';
import type { IssueOptions } from './issue-options.js';
import type { NormalizedClaims, NormalizedIssueOptions } from './normalized-issue-input.js';

/** `buildCredential` の入力（オプション以外の確定済み値）。 */
export interface BuildCredentialInput {
  /** Issuer 識別子（VC の `issuer`）。 */
  readonly issuer: string;
  /** Holder DID（`credentialSubject.id`）。 */
  readonly holderDID: string;
  /**
   * VC のクレーム（`credentialSubject` に展開する）。`normalizeClaims` の戻り値だけを渡せる。
   *
   * `claims.id` は展開後に `holderDID` で**上書きされる**（subject 詐称の防止）。
   */
  readonly claims: NormalizedClaims;
  /** VC の ID（URI）。 */
  readonly id: string;
  /** 発行日時（ISO 8601）。 */
  readonly issuanceDate: string;
  /** Token Status List の `status` 参照（付与しない場合は undefined）。 */
  readonly status?: StatusReference;
}

/**
 * `IssueOptions` と確定済み値から W3C VC を組み立てる。
 *
 * 未指定のオプションに対応する VC フィールドは**プロパティ自体を生やさない**
 * （`undefined` を持つ VC を JWT-VC payload へ載せないため）。
 *
 * `credentialSubject.id` は常に検証済みの `input.holderDID` になる。`claims` を先に展開して
 * `id` を後から書くため、呼び出し側が `claims.id` を渡しても DID 形式検査（code `3006`）を
 * 通っていない値が subject になることはない。
 *
 * ## 呼び出し側は正規化スナップショットを渡すこと（型で強制）
 *
 * `claims` / `opts` は `normalized-issue-input.ts` の正規化関数を通った公称型しか受け取らない
 * 生の `IssueOptions` を渡すと下の `ownProperty` 読みが own アクセサを再評価し、
 * **検査器が見た値と署名済み VC に載る値がずれる**ためである。この型により、
 * 「検証した値」==「署名済み VC に載る値」が**トップレベルの own プロパティ**について成り立つ
 * （スナップショットは 1 段の浅い写しなので、入れ子のアクセサまでは保証しない）。
 *
 * @param input issuer / holderDID / claims / id / issuanceDate / status。
 * @param opts 正規化済みの発行オプション（`normalizeIssueOptions` の戻り値）。
 * @returns 組み立てた W3C VC。
 */
export function buildCredential(
  input: BuildCredentialInput,
  opts: NormalizedIssueOptions,
): VerifiableCredential {
  // 任意プロパティは自身のプロパティに限って読む。ここで組み立てた VC はそのまま
  // Issuer に署名されるため、継承値を拾うと、その項目を**省略した**正当な発行でも汚染値が
  // **署名済み VC** に載る（`expirationDate` = 攻撃者の有効期限、`refreshService` = 攻撃者の
  // 更新エンドポイント、`termsOfUse` / `evidence` = 偽の利用条件・発行根拠、
  // `revocationPropagation` = 失効伝搬ポリシーの緩和）。
  const types = ownProperty<readonly string[]>(opts, 'types');
  const expirationDate = ownProperty<string>(opts, 'expirationDate');
  const credentialSchema = ownProperty<string>(opts, 'credentialSchema');
  const refreshService = ownProperty<IssueOptions['refreshService']>(opts, 'refreshService');
  const status = ownProperty<StatusReference>(input, 'status');
  const evidence = ownProperty<IssueOptions['evidence']>(opts, 'evidence');
  const termsOfUse = ownProperty<IssueOptions['termsOfUse']>(opts, 'termsOfUse');
  const derivedFrom = ownProperty<IssueOptions['derivedFrom']>(opts, 'derivedFrom');
  const revocationPropagation = ownProperty<IssueOptions['revocationPropagation']>(
    opts,
    'revocationPropagation',
  );
  // ブランドは型だけの存在なので実行時のキーには現れない。スプレッド結果の型からも落とすため、
  // 展開前に素の記録型へ広げる（キャストは使わない）。
  const claims: Readonly<Record<string, unknown>> = input.claims;
  return {
    '@context': [VC_V2_CONTEXT],
    type: [VC_TYPE, ...(types ?? [])],
    issuer: input.issuer,
    credentialSubject: { ...claims, id: input.holderDID },
    issuanceDate: input.issuanceDate,
    id: input.id,
    ...(expirationDate !== undefined ? { expirationDate } : {}),
    ...(status !== undefined ? { status } : {}),
    ...(credentialSchema !== undefined
      ? { credentialSchema: { id: credentialSchema, type: 'JsonSchema' } }
      : {}),
    ...(refreshService !== undefined ? { refreshService } : {}),
    ...(evidence !== undefined ? { evidence } : {}),
    ...(termsOfUse !== undefined ? { termsOfUse } : {}),
    ...(derivedFrom !== undefined ? { derivedFrom } : {}),
    ...(revocationPropagation !== undefined ? { revocationPropagation } : {}),
  };
}
