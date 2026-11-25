/**
 * Evidence / Terms of Use 検証モジュールの公開エントリ。
 *
 * 型（`types.ts`）・Evidence 検証（`evidence.ts`）・ToU 評価（`terms-of-use.ts` + `odrl.ts`）を集約して
 * 再エクスポートする。credential モジュールの `index.ts` からさらに再エクスポートされる。
 */

export {
  type EvidenceCheck,
  type EvidenceInterpretation,
  type EvidenceVerificationResult,
  interpretEvidence,
  isLoA,
  type LoA,
  verifyEvidence,
} from './evidence.js';
export type { ToURestriction, UsageContext } from './odrl.js';
export {
  assertVpObject,
  checkTermsOfUse,
  type ToUCheckResult,
  type ToUViolation,
  type VPValidationResult,
  validateTermsOfUseOnPresentation,
} from './terms-of-use.js';
export type {
  EvidenceEntry,
  OdrlConstraint,
  OdrlOperator,
  OdrlRule,
  TermsOfUseEntry,
  ToUCheckOptions,
  UnknownVocabularyPolicy,
} from './types.js';
