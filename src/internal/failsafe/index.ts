/**
 * failsafe モジュールの公開エントリ。
 *
 * FO-ID とポリシー判定、監査レコードの型を再エクスポートする。
 *
 * 判定プリミティブ本体は Foundation の `internal/failsafe-policy/` にあり、本バレルはそれを
 * そのまま再エクスポートして公開 API の形を保つ（Protocol → Foundation の順方向依存）。
 * 本パッケージ固有の実体は Dashboard ログへの監査配線（`dashboard-audit.ts`）だけである。
 */

export {
  createFailOpenWindow,
  DEFAULT_FAIL_OPEN_MAX_SECONDS,
  decideFailSafe,
  FAIL_OPEN_AUDIT_EVENTS,
  FAIL_OPEN_IDS,
  type FailOpenId,
  type FailOpenWindow,
  type FailSafeAuditContext,
  type FailSafeAuditRecord,
  type FailSafeDecision,
  type FailSafePolicy,
  type FailSafeSeverity,
  type FailSafeWarning,
  type ResolveFailOpenParams,
  resolveFailOpen,
  UNKNOWN_POLICY_EVENT_AUDIT,
} from '../failsafe-policy/index.js';
export {
  createDashboardLogAuditRecorder,
  FAIL_OPEN_LOG_ENTRY_TYPE,
} from './dashboard-audit.js';
