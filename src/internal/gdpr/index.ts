/**
 * 保持 VC の処理制限・同意撤回・削除、Dashboard ログの署名・検証・エクスポートとインポートを提供する。
 * ログの検証鍵には固定鍵または `kid` からのリゾルバを渡せる。鍵を解決できないエントリは `keyUnresolved` として報告する。
 *
 * 公開前に特別カテゴリ属性を検出するヘルパ、提示と域外転送の記録、DSR / DPO 連絡先の発見も提供する。
 */

export {
  assertNoSpecialCategoryOnChain,
  findSpecialCategoryAttributes,
  SPECIAL_CATEGORY_ATTRIBUTES,
} from '../special-category.js';
export { CredentialStore } from './credential-store/index.js';
export { DASHBOARD_LOG_EXPORT_MIME, DashboardLog } from './dashboard-log/dashboard-log.js';
export type { DashboardLogVerifierKey } from './dashboard-log/dashboard-log-import.js';
export {
  DASHBOARD_LOG_KEY_PREFIX,
  DASHBOARD_LOG_TAIL_ANCHOR_KEY,
  type DashboardLogStorage,
} from './dashboard-log/dashboard-log-shared.js';
export {
  type DashboardLogDeletionRecords,
  type DashboardLogIssue,
  type DashboardLogIssueReason,
  type DashboardLogTrimWatermark,
  type DashboardLogVerification,
  type DashboardLogVerifierKeyResolver,
  resolveDeletionRecords,
  verifyDashboardLogChain,
} from './log-integrity/chain.js';
export {
  buildPresentationEventPayload,
  logPresentationEvent,
  PRESENTATION_LOG_TYPE,
  type PresentationEventInput,
  type PresentationEventPayload,
} from './presentation-log.js';
export {
  recordTransferWarning,
  type TransferWarning,
  type TransferWarningSource,
} from './transfer-warning.js';
export type {
  AuthFailurePayload,
  ConsentRevokedPayload,
  ConsentScope,
  CorrectionRequestPayload,
  CredentialDeletedPayload,
  CredentialRecord,
  DashboardLogEntry,
  DeletedLogEntryRecord,
  DpoContactMetadata,
  DsrEndpointMetadata,
  LogEntryDeletedPayload,
  LogEntryType,
  LogFilter,
  PresentedToEntry,
  TransferWarningPayload,
  UnlockPayload,
} from './types.js';
export { discoverDpoContact, discoverDsrEndpoint } from './well-known-discovery.js';
