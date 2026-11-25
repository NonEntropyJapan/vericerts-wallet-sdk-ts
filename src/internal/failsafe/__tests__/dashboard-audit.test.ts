/**
 * Fail-open 監査レコードの Dashboard ログ記録（`createDashboardLogAuditRecorder`）の単体テスト。
 *
 * Fail-open で通過した場合もユーザーが拒否した場合も、判断結果を署名付きで Dashboard ログに追記する。
 *
 * 検証内容:
 * - `resolveFailOpen` に配線すると、通過時に JWS 署名付きの `failOpenPolicy` エントリが追記される。
 * - payload が 監査フィールド（policy_event / user_consent / override / verifier / vc_id / trace_id）
 *   と一致し、計時キー（Status List URI）は混入しない。
 * - 不同意（`rejected`）でも追記される。
 * - 連続追記で prevHash chain が連結される（改ざん検知の連続性）。
 * - 追記に失敗した場合は Fail-open が成立しない（記録は省略不可）。
 */

import { describe, expect, it } from 'bun:test';
import { MemoryStorage } from '../../../storage/storage.js';
import { decodeCompactJws, verifyWithJwk } from '../../credential/vc/jws.js';
import { resolveFailOpen } from '../../failsafe-policy/gate.js';
import { createFailOpenWindow } from '../../failsafe-policy/policy.js';
import { fixedNow, testSigner } from '../../gdpr/__tests__/dashboard-log/dashboard-log-helpers.js';
import { DashboardLog } from '../../gdpr/dashboard-log/dashboard-log.js';
import { createDashboardLogAuditRecorder, FAIL_OPEN_LOG_ENTRY_TYPE } from '../dashboard-audit.js';

const KEY = 'https://issuer.example/status/1';

/** DashboardLog に配線した記録先を組み立てる。 */
function setup(): {
  log: DashboardLog;
  onPolicyEvent: ReturnType<typeof createDashboardLogAuditRecorder>;
  signer: ReturnType<typeof testSigner>;
} {
  const signer = testSigner();
  const log = new DashboardLog(new MemoryStorage(), fixedNow('2026-08-27T00:00:00.000Z'));
  return { log, onPolicyEvent: createDashboardLogAuditRecorder(log, signer), signer };
}

describe('createDashboardLogAuditRecorder', () => {
  it('Fail-open 通過時に JWS 署名付きの failOpenPolicy エントリが Dashboard ログへ追記される', async () => {
    const s = setup();
    const warning = await resolveFailOpen({
      policyEvent: 'FO-1',
      policy: { suppressPrompt: ['FO-1'] },
      window: createFailOpenWindow(),
      key: KEY,
      nowSeconds: 1_000,
      onPolicyEvent: s.onPolicyEvent,
      auditContext: { verifier: 'sha256:rp', vc_id: 'vc-1', trace_id: 'trace-1' },
    });

    expect(warning).toEqual({ policyEvent: 'FO-1', auditEvent: 'status_check_unreachable' });
    const entries = await s.log.list();
    expect(entries).toHaveLength(1);
    const entry = entries[0];
    expect(entry?.type).toBe(FAIL_OPEN_LOG_ENTRY_TYPE);
    expect(entry?.payload).toEqual({
      policy_event: 'FO-1',
      audit_event: 'status_check_unreachable',
      user_consent: 'accepted',
      override: { suppressPrompt: ['FO-1'] },
      verifier: 'sha256:rp',
      vc_id: 'vc-1',
      trace_id: 'trace-1',
    });
    // 署名（コンパクト JWS）が signer の公開鍵で検証できる。
    const decoded = decodeCompactJws(entry?.signature as string);
    expect(verifyWithJwk('ES256K', decoded, s.signer.publicKeyJwk)).toBe(true);
    expect(decoded.payload.type).toBe(FAIL_OPEN_LOG_ENTRY_TYPE);
    // 計時キー（Status List URI）は監査レコードに出さない。
    expect(JSON.stringify(entry)).not.toContain(KEY);
  });

  it('同意が得られなかった場合（rejected）も追記される', async () => {
    const s = setup();
    const warning = await resolveFailOpen({
      policyEvent: 'FO-1',
      window: createFailOpenWindow(),
      key: KEY,
      nowSeconds: 1_000,
      requestConsent: () => false,
      onPolicyEvent: s.onPolicyEvent,
    });

    expect(warning).toBeUndefined();
    const entries = await s.log.list();
    expect(entries).toHaveLength(1);
    expect(entries[0]?.payload.user_consent).toBe('rejected');
  });

  it('連続する Fail-open 記録は prevHash chain で連結される', async () => {
    const s = setup();
    const window = createFailOpenWindow();
    const params = {
      policyEvent: 'FO-1',
      policy: { suppressPrompt: ['FO-1'] },
      window,
      key: KEY,
      onPolicyEvent: s.onPolicyEvent,
    } as const;
    await resolveFailOpen({ ...params, nowSeconds: 1_000 });
    await resolveFailOpen({ ...params, nowSeconds: 1_010 });

    const entries = await s.log.list();
    expect(entries).toHaveLength(2);
    expect(entries[0]?.prevHash).toBeNull();
    expect(entries[1]?.prevHash).not.toBeNull();
  });

  it('Dashboard ログへの追記が失敗したら Fail-open は成立しない', async () => {
    const signer = testSigner();
    const failingLog = {
      append: async (): Promise<never> => {
        throw new Error('storage unavailable');
      },
    };
    const warning = await resolveFailOpen({
      policyEvent: 'FO-1',
      policy: { suppressPrompt: ['FO-1'] },
      window: createFailOpenWindow(),
      key: KEY,
      nowSeconds: 1_000,
      onPolicyEvent: createDashboardLogAuditRecorder(
        failingLog as unknown as Pick<DashboardLog, 'append'>,
        signer,
      ),
    });
    expect(warning).toBeUndefined();
  });
});
