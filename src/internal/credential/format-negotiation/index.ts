/**
 * VC フォーマットネゴシエーションの公開エントリ。
 *
 * 選択（select）/ 被覆判定（canFulfillFormats）/ 複数形式提示（multi-format）/ 能力評価
 * （capability）を分割し、本バレルから再エクスポートする。
 */

export {
  type EvaluateFormatCapabilityOptions,
  evaluateFormatCapability,
  type FormatDescriptor,
} from './capability.js';
export {
  type BuildMultiFormatVPOptions,
  buildMultiFormatVP,
  type DescriptorMapEntry,
  type MultiFormatAuditEntry,
  type MultiFormatVPToken,
  type PresentationSubmission as MultiFormatPresentationSubmission,
} from './multi-format.js';
export {
  canFulfillFormats,
  type SelectBestVCOptions,
  selectBestVC,
} from './select.js';
export {
  type CredentialKeyBinding,
  type FormatCapabilityResult,
  type FormatConstraint,
  type FormatCoverage,
  isSelectiveDisclosureCapable,
  type LimitDisclosure,
  MAX_MULTI_FORMAT_COUNT,
  type NegotiableCredential,
  PRIVACY_TIER,
  SELECTIVE_DISCLOSURE_FORMATS,
  type VCFormat,
  type VCSelection,
  type VpFormatRequirement,
} from './types.js';
