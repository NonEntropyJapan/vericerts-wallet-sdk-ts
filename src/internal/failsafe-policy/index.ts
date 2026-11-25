/**
 * Fail-open / Fail-closed 判定プリミティブの公開エントリ（Foundation）。
 *
 * FO-ID に基づく判定、ポリシーの上書き、監査レコードの型を提供する。
 * 判定結果を GDPR Dashboard ログに記録するアダプターは `internal/failsafe/dashboard-audit.ts` が提供する。
 *
 * **配置の理由**: `credential` / `issuer`（Domain）が `decideFailSafe` / `resolveFailOpen` /
 * `createFailOpenWindow` を参照しており、判定プリミティブが Protocol にあると Domain → Protocol の
 * 逆方向依存になる。本パッケージの依存は `cache`（Foundation）と
 * `own-property.ts`（横断）だけなので Foundation に置ける。
 */

export { type ResolveFailOpenParams, resolveFailOpen } from './gate.js';
export {
  createFailOpenWindow,
  DEFAULT_FAIL_OPEN_MAX_SECONDS,
  decideFailSafe,
  FAIL_OPEN_AUDIT_EVENTS,
  FAIL_OPEN_IDS,
  type FailOpenWindow,
  UNKNOWN_POLICY_EVENT_AUDIT,
} from './policy.js';
export type {
  FailOpenId,
  FailSafeAuditContext,
  FailSafeAuditRecord,
  FailSafeDecision,
  FailSafePolicy,
  FailSafeSeverity,
  FailSafeWarning,
} from './types.js';
