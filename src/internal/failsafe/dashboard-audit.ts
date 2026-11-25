/**
 * Fail-open 監査レコードを署名付き Dashboard ログへ追記する。
 *
 * `resolveFailOpen` の `onPolicyEvent` へ渡して使う。
 *
 * 署名（コンパクト JWS）と prevHash chain は既存の `DashboardLog.append` が担うため、本モジュールは
 * 監査レコードを Dashboard ログのエントリ種別 `failOpenPolicy` に載せ替えるだけに徹する。
 *
 * セキュリティ上の注意:
 * - payload は `FailSafeAuditRecord` の項目のみ。Status List URI などの計時キーや JWT は
 *   含めない。呼び出し側が `auditContext` に渡す識別子はハッシュ等である前提。
 */

import type { CredentialSigner } from '../credential/index.js';
import type { FailSafeAuditRecord } from '../failsafe-policy/types.js';
import type { DashboardLog } from '../gdpr/dashboard-log/dashboard-log.js';
import type { LogEntryType } from '../gdpr/types.js';

/** Fail-open 判定を Dashboard ログに記録する際のエントリ種別。 */
export const FAIL_OPEN_LOG_ENTRY_TYPE: LogEntryType = 'failOpenPolicy';

/**
 * `FailSafeAuditRecord` を Dashboard ログへ署名付きで追記する記録先を作る。
 *
 * 追記は `DashboardLog.append` に委譲するため、各エントリは JWS 署名と prevHash chain を持つ。
 * 同意を得られなかった場合も `user_consent: 'rejected'` で追記する。
 *
 * 追記が失敗した場合は例外がそのまま `resolveFailOpen` に伝わり、記録できなかった Fail-open は
 * 成立しない（Fail-closed に倒れる）。
 *
 * @param log 追記先の Dashboard ログ。
 * @param signer JWS 署名鍵（`CredentialSigner`）。
 * @returns `resolveFailOpen` の `onPolicyEvent` に渡せる記録先。
 */
export function createDashboardLogAuditRecorder(
  log: Pick<DashboardLog, 'append'>,
  signer: CredentialSigner,
): (record: FailSafeAuditRecord) => Promise<void> {
  return async (auditRecord: FailSafeAuditRecord): Promise<void> => {
    await log.append(FAIL_OPEN_LOG_ENTRY_TYPE, { ...auditRecord }, signer);
  };
}
