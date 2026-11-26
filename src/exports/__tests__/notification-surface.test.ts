/**
 * Credential Notification API の公開エクスポート面の回帰テスト。
 *
 * SubscribeCredentialNotification（Holder 側）/
 * ProcessCredentialNotification（Issuer 側）は `internal/credential/notification/` に実装済みで、
 * 内部バレル `internal/credential/index.ts` からも再エクスポートされていた。しかし
 * `src/exports/*.ts` のどの公開バレルにも載っていなかったため、SDK 利用者は
 * `import { subscribeCredentialNotification } from '@vericerts/vericerts-wallet-sdk'` すらできず、
 * 実装があるのに到達不能という状態だった。
 *
 * これらのソースは `@experimental` / `@stable` / `@internal` のいずれの印も持たない。
 * pre-1.0 の無タグ API は暗黙の実験的 API としてメインバレルに残す。
 * よってサブパス `./experimental` ではなくメインバレル（`exports/credential.ts` → `src/index.ts`）
 * から import できることを固定する。
 *
 * 内部パス（`internal/credential/notification/*.js`）から import すると公開面の欠落を
 * 検知できないため、被テスト API は必ず公開バレル（`sdk`）経由で import すること。
 */

import { describe, expect, test } from 'bun:test';
import * as sdk from '../../index.js';
import * as experimental from '../experimental.js';

const ISSUER_URL = 'https://issuer.example.com/notification';

/** CredentialNotificationEvent として受理される通知ペイロード。 */
const REVOKED_PAYLOAD = {
  event: 'credential_revoked',
  notification_id: 'notif-721',
  notification_issued_at: '2026-09-11T00:00:00Z',
  credential_configuration_id: 'UniversityDegree',
  reason: 'compromised',
} as const;

/** 非同期 dispatch（`void handler(...)`）を待つ。 */
async function flush(): Promise<void> {
  await new Promise((resolve) => setTimeout(resolve, 0));
}

describe('公開エクスポート: Credential Notification', () => {
  test('通知 API がメインバレルから import できる（experimental サブパスには載らない）', () => {
    // 実装済みなのに公開バレル未配線だった 4 関数。
    expect(typeof sdk.subscribeCredentialNotification).toBe('function');
    expect(typeof sdk.processCredentialNotification).toBe('function');
    expect(typeof sdk.deliverWebhook).toBe('function');
    expect(typeof sdk.parseNotificationEvent).toBe('function');
    // 定数も同じメインバレルから取れる（poll 間隔を利用者が既定値と比較できる）。
    expect(typeof sdk.DEFAULT_NOTIFICATION_POLL_INTERVAL_MS).toBe('number');

    // 無タグ API はサブパスへ移送しない。
    const experimentalNames = experimental as unknown as Record<string, unknown>;
    expect(experimentalNames.subscribeCredentialNotification).toBeUndefined();
    expect(experimentalNames.processCredentialNotification).toBeUndefined();
  });

  test('公開型が型注釈として使える（型だけの欠落も検知する）', () => {
    // 値だけ通っていて型が非公開だと利用者は引数を組み立てられない。型注釈で固定する。
    const mode: sdk.NotificationMode = 'webhook';
    const req: sdk.CredentialNotificationRequest = {
      notification_id: REVOKED_PAYLOAD.notification_id,
      event: 'credential_accepted',
    };
    const entry: sdk.NotificationAuditEntry = {
      notification_id: req.notification_id,
      event: req.event,
    };
    const unsubscribe: sdk.PushUnsubscribe = () => {};

    expect(mode).toBe('webhook');
    expect(entry.notification_id).toBe('notif-721');
    expect(unsubscribe()).toBeUndefined();
  });

  test('webhook モードの購読から配送までを公開 API だけで通せる', async () => {
    const received: sdk.CredentialNotificationEvent[] = [];
    const deps: sdk.SubscribeDependencies = {
      generateId: () => 'sub-721-webhook',
      registerWebhook: async (_issuerURL, id) => `https://wallet.example.com/hook/${id}`,
    };

    const subscription: sdk.NotificationSubscription = await sdk.subscribeCredentialNotification(
      ISSUER_URL,
      'webhook',
      async (event) => {
        received.push(event);
      },
      deps,
    );
    expect(subscription.mode).toBe('webhook');
    expect(subscription.endpoint).toBe('https://wallet.example.com/hook/sub-721-webhook');

    // 受信ペイロードが公開 deliverWebhook 経由で handler まで届く。
    expect(sdk.deliverWebhook(subscription.id, REVOKED_PAYLOAD)).toBe(true);
    await flush();
    expect(received).toHaveLength(1);
    expect(received[0]?.event).toBe('credential_revoked');
    expect(received[0]?.notification_id).toBe('notif-721');
    expect(received[0]?.reason).toBe('compromised');

    await subscription.unsubscribe();
    expect(sdk.deliverWebhook(subscription.id, REVOKED_PAYLOAD)).toBe(false);
  });

  test('公開バレル経由でも非 HTTPS の issuerURL は拒否される', async () => {
    await expect(
      sdk.subscribeCredentialNotification('http://issuer.example.com/n', 'poll', async () => {}),
    ).rejects.toMatchObject({ code: sdk.ErrorCodes.NOTIFICATION_ACCESS_TOKEN_INVALID });
  });

  test('processCredentialNotification が成功パスで監査ログを記録する', async () => {
    const audit: sdk.NotificationAuditEntry[] = [];
    const deps: sdk.ProcessNotificationDependencies = {
      verifyAccessToken: (token) => token === 'valid-token',
      resolveNotificationId: (id) => id === 'notif-721',
      recordAudit: (entry) => {
        audit.push(entry);
      },
    };
    const req: sdk.CredentialNotificationRequest = {
      notification_id: 'notif-721',
      event: 'credential_accepted',
      event_description: 'stored in wallet',
    };

    await sdk.processCredentialNotification(req, 'valid-token', deps);

    expect(audit).toHaveLength(1);
    expect(audit[0]?.notification_id).toBe('notif-721');
    expect(audit[0]?.event).toBe('credential_accepted');
    expect(audit[0]?.event_description).toBe('stored in wallet');
  });

  test('processCredentialNotification のエラーも公開エラーコードに正規化される', async () => {
    const audit: sdk.NotificationAuditEntry[] = [];
    const deps: sdk.ProcessNotificationDependencies = {
      verifyAccessToken: (token) => token === 'valid-token',
      resolveNotificationId: (id) => id === 'notif-721',
      recordAudit: (entry) => {
        audit.push(entry);
      },
    };

    // トークン不正 → 3041。
    await expect(
      sdk.processCredentialNotification(
        { notification_id: 'notif-721', event: 'credential_accepted' },
        'expired-token',
        deps,
      ),
    ).rejects.toMatchObject({ code: sdk.ErrorCodes.NOTIFICATION_ACCESS_TOKEN_INVALID });

    // 未知の notification_id → 3042。
    await expect(
      sdk.processCredentialNotification(
        { notification_id: 'unknown-notif', event: 'credential_accepted' },
        'valid-token',
        deps,
      ),
    ).rejects.toMatchObject({ code: sdk.ErrorCodes.NOTIFICATION_ID_UNKNOWN });

    // 失敗時は監査ログを書かない。
    expect(audit).toHaveLength(0);
  });

  test('parseNotificationEvent が公開バレル経由で正規化と棄却を行う', () => {
    const parsed: sdk.CredentialNotificationEvent | undefined =
      sdk.parseNotificationEvent(REVOKED_PAYLOAD);
    expect(parsed?.event).toBe('credential_revoked');
    expect(parsed?.credential_configuration_id).toBe('UniversityDegree');

    // 未知種別は棄却する（不正通知でハンドラを起動しない）。
    expect(sdk.parseNotificationEvent({ ...REVOKED_PAYLOAD, event: 'bogus' })).toBeUndefined();
  });
});
