/**
 * presentation-exchange モジュールの公開エントリ（内部バレル）。
 *
 * DIF Presentation Exchange v2.0 の VP 要件記述（Presentation Definition）の評価と
 * Presentation Submission の構築・検証を提供する。
 *
 * DCQL（OID4VP Draft 24+）の評価は `auth/dcql/dcql.ts` が担い、本モジュールは PEx v2 側を担当する。
 * 両者は同じ `QueryableCredential` / `CredentialMatch`
 * 型を共有し、統一的な VC 候補マッチングエンジンとして振る舞う。本モジュールが auth/ に属さず
 * 独立ドメインなのは、PEx v2 が OID4VP 固有ではなく SIOPv2 など他プロトコルからも参照される
 * 汎用の要件記述フォーマットだからである（依存方向は presentation-exchange → auth/dcql/dcql.ts の
 * 型参照のみ）。
 *
 * - definition.ts: Presentation Definition の型と `parsePresentationDefinition`。
 * - evaluate.ts:   `evaluatePresentationDefinition` による VC 候補評価。
 * - submission.ts: `buildPresentationSubmission` / `validatePresentationSubmission`。
 *
 * いずれも署名・暗号プリミティブを伴わない純粋関数である（選択的開示の実行は credential
 * ドメインの責務）。
 */

export { createPexBudget, type PexBudget } from './budget.js';
export {
  type Constraints,
  type Field,
  type FormatRequirement,
  type InputDescriptor,
  type PresentationDefinition,
  parsePresentationDefinition,
} from './definition.js';
export {
  evaluatePresentationDefinition,
  evaluatePresentationDefinitionWithBudget,
} from './evaluate.js';
export type { JSONSchemaFilter } from './filter-definition.js';
export {
  type BuildPresentationSubmissionOptions,
  buildPresentationSubmission,
  type DescriptorMap,
  type PresentationSubmission,
  validatePresentationSubmission,
} from './submission.js';
