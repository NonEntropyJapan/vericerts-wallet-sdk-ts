/**
 * trust/arf モジュールの公開エントリ。
 *
 * ARF（Architecture and Reference Framework）Trust Model の Trust Anchor 取得（Wallet Provider
 * Registry の Ed25519 署名付き Catalogue）、ETSI Trusted List（trust/etsi-tsl）との対応付け
 * （ARF ⇔ TSL マッピング）、および OpenID Federation（trust/federation）との対応付け
 * （Federation ⇔ ARF マッピング）を再エクスポートする。さらに 3 層統合信頼判定
 * （evaluateTrust）とその判定結果ログ記録（decision-log.ts）を再エクスポートする。
 */

export type {
  ArfCatalogueEntry,
  ArfCatalogueGeneration,
  ArfEntryRole,
  ArfTrustAnchorFetcher,
  ArfTrustAnchorSet,
  LoadArfTrustAnchorOptions,
} from './arf-types.js';
export { loadArfTrustAnchor } from './catalogue.js';
export {
  evaluateTrustWithLogging,
  type TrustDecisionLogRecord,
  type TrustDecisionLogSink,
  toTrustDecisionLogRecord,
} from './decision-log.js';
export { evaluateTrust } from './evaluate.js';
export {
  type FederationArfMapping,
  type FederationArfMatch,
  mapFederationToArf,
} from './federation-mapping.js';
export {
  type ArfTslMapping,
  type ArfTslMatch,
  arfEntrySpki,
  mapArfToTsl,
  type TslServiceCertificate,
} from './mapping.js';
export type {
  CachedTrustDecision,
  EvaluateTrustInput,
  LayerStatus,
  LayerVerdict,
  TrustDecision,
  TrustDecisionCode,
  TrustDecisionWarning,
  TrustLayer,
} from './trust-decision-types.js';
