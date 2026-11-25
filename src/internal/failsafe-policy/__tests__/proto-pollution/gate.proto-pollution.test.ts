/**
 * `resolveFailOpen` の `Object.prototype` 汚染耐性テスト。
 *
 * `params.onPolicyEvent` / `params.requestConsent` / `params.policy` をプロトタイプ鎖で読むと、
 * これらを**省略した**正当な呼び出しが fail-open 側へ反転する:
 *
 * - `onPolicyEvent`: 汚染値が「監査シンクあり」を満たし、監査記録なしで fail-open が成立する。
 * - `requestConsent`: 汚染値が truthy を返せば `promptRequired` の同意がユーザー操作なしで成立する。
 * - `policy`: 汚染した override が `deny` 判定を許可側へ倒す。
 *
 * いずれも「汚染下でも fail-closed（`undefined` を返す）のまま」を期待値とする。
 */

import { describe, expect, it } from 'bun:test';
import { withPollutedPrototypeAsync } from '../../../__tests__/prototype-pollution.fixtures.js';
import { resolveFailOpen } from '../../gate.js';
import { createFailOpenWindow } from '../../policy.js';
import type { FailSafeAuditRecord } from '../../types.js';

const KEY = 'https://issuer.example/status/1';

describe('resolveFailOpen の Object.prototype 汚染耐性', () => {
  it('継承した onPolicyEvent は監査シンクとして採用しない（記録なし fail-open を防ぐ）', async () => {
    const leaked: FailSafeAuditRecord[] = [];
    const warning = await withPollutedPrototypeAsync(
      { onPolicyEvent: (r: FailSafeAuditRecord) => leaked.push(r) },
      () =>
        resolveFailOpen({
          policyEvent: 'FO-1',
          window: createFailOpenWindow(),
          key: KEY,
          nowSeconds: 1_000,
          // onPolicyEvent は渡していない。
        }),
    );
    // 監査シンクが無い以上 fail-open は成立しない。
    expect(warning).toBeUndefined();
    // 汚染シンクが呼ばれていないこと（呼ばれていたら継承値を採用している）。
    expect(leaked).toEqual([]);
  });

  it('継承した requestConsent はユーザー同意として採用しない', async () => {
    const records: FailSafeAuditRecord[] = [];
    let consentCalls = 0;
    const warning = await withPollutedPrototypeAsync(
      {
        requestConsent: (): boolean => {
          consentCalls += 1;
          return true;
        },
      },
      () =>
        resolveFailOpen({
          policyEvent: 'FO-1',
          window: createFailOpenWindow(),
          key: KEY,
          nowSeconds: 1_000,
          onPolicyEvent: (r): void => {
            records.push(r);
          },
          // requestConsent は渡していない ＝ 同意を取る手段が無い。
        }),
    );
    expect(warning).toBeUndefined();
    expect(consentCalls).toBe(0);
    expect(records).toEqual([
      {
        policy_event: 'FO-1',
        audit_event: 'status_check_unreachable',
        user_consent: 'rejected',
        override: {},
      },
    ]);
  });

  it('継承した policy override は判定にも監査レコードにも入らない', async () => {
    const records: FailSafeAuditRecord[] = [];
    const warning = await withPollutedPrototypeAsync({ policy: { escalate: ['FO-1'] } }, () =>
      resolveFailOpen({
        policyEvent: 'FO-1',
        window: createFailOpenWindow(),
        key: KEY,
        nowSeconds: 1_000,
        onPolicyEvent: (r): void => {
          records.push(r);
        },
        requestConsent: () => true,
        // policy は渡していない。
      }),
    );
    // 継承した escalate を拾えば `deny` になり記録が 0 件になる。既定どおり許可 + 記録が正。
    expect(warning).toEqual({ policyEvent: 'FO-1', auditEvent: 'status_check_unreachable' });
    expect(records).toHaveLength(1);
    expect(records[0]?.override).toEqual({});
  });

  it('継承した auditContext は監査レコードへ混入しない', async () => {
    const records: FailSafeAuditRecord[] = [];
    await withPollutedPrototypeAsync({ auditContext: { tenant_id: 'attacker' } }, () =>
      resolveFailOpen({
        policyEvent: 'FO-1',
        window: createFailOpenWindow(),
        key: KEY,
        nowSeconds: 1_000,
        onPolicyEvent: (r): void => {
          records.push(r);
        },
      }),
    );
    expect(records).toHaveLength(1);
    expect(records[0]).not.toHaveProperty('tenant_id');
  });

  it('own の allow を持たない window は Object.prototype 汚染下でも受理しない', async () => {
    // `params.window` 自体は own プロパティとして正しく渡しているが、中身が空オブジェクト
    // （own の allow を持たない）。`window.allow` を素のドットアクセスで検証すると
    // `Object.prototype.allow` の汚染を拾い、攻撃者の allow が常に true を返して
    // fail-open が無条件に成立してしまう。
    const records: FailSafeAuditRecord[] = [];
    let attackerAllowCalls = 0;
    const warning = await withPollutedPrototypeAsync(
      {
        allow: (): boolean => {
          attackerAllowCalls += 1;
          return true;
        },
      },
      () =>
        resolveFailOpen({
          policyEvent: 'FO-1',
          window: {} as ReturnType<typeof createFailOpenWindow>,
          key: KEY,
          nowSeconds: 1_000,
          onPolicyEvent: (r): void => {
            records.push(r);
          },
          requestConsent: () => true,
        }),
    );
    expect(warning).toBeUndefined();
    expect(attackerAllowCalls).toBe(0);
    expect(records).toEqual([]);
  });

  it('明示的に渡した onPolicyEvent / requestConsent は従来どおり機能する（正常系）', async () => {
    const records: FailSafeAuditRecord[] = [];
    const warning = await resolveFailOpen({
      policyEvent: 'FO-1',
      window: createFailOpenWindow(),
      key: KEY,
      nowSeconds: 1_000,
      onPolicyEvent: (r): void => {
        records.push(r);
      },
      requestConsent: () => true,
    });
    expect(warning).toEqual({ policyEvent: 'FO-1', auditEvent: 'status_check_unreachable' });
    expect(records).toHaveLength(1);
    expect(records[0]?.user_consent).toBe('accepted');
  });
});
