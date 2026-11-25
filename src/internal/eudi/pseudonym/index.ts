/**
 * eudi/pseudonym モジュールの公開エントリ。
 *
 * RP 別 Pseudonym 鍵の HKDF 派生・Pseudonym Attestation 発行・SIOPv2 ログイン用 ID Token 生成を
 * 再エクスポートする。facade（`wallet.ts` / `index.ts`）への配線は統合担当が行う。
 */

export {
  issuePseudonymAttestation,
  type PseudonymAttestationOptions,
} from './attestation.js';
export {
  canonicalizeRpIdentifier,
  computePseudonymSubject,
  derivePseudonym,
} from './derive.js';
export { type PresentPseudonymOptions, presentPseudonym } from './siop.js';
export {
  PSEUDONYM_HKDF_INFO,
  PSEUDONYM_SUBJECT_PREFIX,
  PSEUDONYM_VCT,
  type PseudonymAttestation,
  type PseudonymAttestationClaims,
  type PseudonymConfirmation,
  type PseudonymIdToken,
  type PseudonymKey,
  type SiopRequest,
} from './types.js';
