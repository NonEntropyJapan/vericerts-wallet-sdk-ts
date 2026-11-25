/**
 * Credential Notification Endpoint（Issuer）の統合テスト。
 *
 * 検証内容: processCredentialNotification のトークン検証（3041）・notification_id 解決（3042）・
 * 監査記録、不正 event の棄却、event_description 省略、async DI の await。
 *
 * トークン検証・ID 解決・監査記録はすべて DI スタブで注入する。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes } from '../../../errors.js';
import { processCredentialNotification } from '../process.js';
import type { CredentialNotificationRequest, ProcessNotificationDependencies } from '../types.js';

const okReq: CredentialNotificationRequest = {
  notification_id: 'notif-1',
  event: 'credential_accepted',
  event_description: 'stored',
};

function makeDeps(overrides: Partial<ProcessNotificationDependencies> = {}): {
  deps: ProcessNotificationDependencies;
  audit: unknown[];
} {
  const audit: unknown[] = [];
  return {
    audit,
    deps: {
      verifyAccessToken: () => true,
      resolveNotificationId: () => true,
      recordAudit: (entry) => {
        audit.push(entry);
      },
      ...overrides,
    },
  };
}

describe('processCredentialNotification — Issuer Notification Endpoint（統合）', () => {
  it('正常系: トークン検証 → id 解決 → 監査記録', async () => {
    const { deps, audit } = makeDeps();
    await processCredentialNotification(okReq, 'token', deps);
    expect(audit).toHaveLength(1);
    expect(audit[0]).toEqual({
      notification_id: 'notif-1',
      event: 'credential_accepted',
      event_description: 'stored',
    });
  });

  it('トークン不正で NOTIFICATION_ACCESS_TOKEN_INVALID（3041）', async () => {
    const { deps, audit } = makeDeps({ verifyAccessToken: () => false });
    await expect(processCredentialNotification(okReq, 'bad', deps)).rejects.toMatchObject({
      code: ErrorCodes.NOTIFICATION_ACCESS_TOKEN_INVALID,
    });
    expect(audit).toHaveLength(0);
  });

  it('未知の notification_id で NOTIFICATION_ID_UNKNOWN（3042）', async () => {
    const { deps, audit } = makeDeps({ resolveNotificationId: () => false });
    await expect(processCredentialNotification(okReq, 'token', deps)).rejects.toMatchObject({
      code: ErrorCodes.NOTIFICATION_ID_UNKNOWN,
    });
    expect(audit).toHaveLength(0);
  });

  it('不正な event 種別で NOTIFICATION_ID_UNKNOWN（3042）', async () => {
    const { deps } = makeDeps();
    const badReq = {
      notification_id: 'notif-1',
      event: 'bogus',
    } as unknown as CredentialNotificationRequest;
    await expect(processCredentialNotification(badReq, 'token', deps)).rejects.toMatchObject({
      code: ErrorCodes.NOTIFICATION_ID_UNKNOWN,
    });
  });

  it('event_description 無しでも監査記録できる', async () => {
    const { deps, audit } = makeDeps();
    await processCredentialNotification(
      { notification_id: 'notif-2', event: 'credential_failure' },
      'token',
      deps,
    );
    expect(audit[0]).toEqual({ notification_id: 'notif-2', event: 'credential_failure' });
  });

  it('async な verifyAccessToken / resolveNotificationId を await する', async () => {
    const { deps, audit } = makeDeps({
      verifyAccessToken: async () => true,
      resolveNotificationId: async () => true,
    });
    await processCredentialNotification(okReq, 'token', deps);
    expect(audit).toHaveLength(1);
  });
});
