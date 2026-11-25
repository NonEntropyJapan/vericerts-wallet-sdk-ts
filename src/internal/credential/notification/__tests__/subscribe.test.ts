/**
 * Credential Notification 購読（Holder）のユニット / 統合テスト。
 *
 * 検証内容:
 * - parseNotificationEvent: 正規化と未知種別 / 欠落フィールドの棄却。
 * - チャネル登録（subscribeCredentialNotification）: poll / webhook / push 各モードのハンドル生成、
 *   非 HTTPS 拒否、購読 ID 生成、unsubscribe 冪等性。
 * - イベント処理（統合）: poll ポーリング → handler 配送、HTTP エラー時の非配送、handler 例外の継続、
 *   GET を body なしで送る回帰、push 配送。
 * - WebHook 受信（deliverWebhook）: 購読済み ID への配送、未知 ID / 不正ペイロード / 解除後で false。
 *
 * ネットワーク・タイマー・push チャネルはすべて DI スタブで注入し、実 HTTP / 実タイマーは使わない。
 */

import { describe, expect, it } from 'bun:test';
import type { FetchLike } from '../../../auth/oid4vci/oid4vci.js';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import {
  deliverWebhook,
  parseNotificationEvent,
  subscribeCredentialNotification,
} from '../subscribe.js';
import type { CredentialNotificationEvent } from '../types.js';
import { DEFAULT_NOTIFICATION_POLL_INTERVAL_MS } from '../types.js';

const ISSUER_URL = 'https://issuer.example/notification';

const ACCEPTED_EVENT = {
  event: 'credential_accepted',
  notification_id: 'notif-1',
  notification_issued_at: '2026-07-01T00:00:00Z',
  credential_configuration_id: 'UniversityDegree',
  transaction_id: 'tx-1',
};

/** JSON 本文を 200 で返す FetchLike を作る。 */
function jsonFetch(body: unknown): FetchLike {
  return async () =>
    new Response(JSON.stringify(body), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    });
}

/** タスクを即時に実行できる手動スケジューラ。schedule DI に注入する。 */
function manualScheduler(): {
  schedule: (task: () => void, intervalMs: number) => () => void;
  fire: () => void;
  intervalMs: number | undefined;
  stopped: boolean;
} {
  const state = {
    task: undefined as (() => void) | undefined,
    intervalMs: undefined as number | undefined,
    stopped: false,
    schedule(task: () => void, intervalMs: number): () => void {
      state.task = task;
      state.intervalMs = intervalMs;
      return () => {
        state.stopped = true;
      };
    },
    fire(): void {
      state.task?.();
    },
  };
  return state as unknown as ReturnType<typeof manualScheduler>;
}

/** 非同期配送を待つ（microtask + macrotask フラッシュ）。 */
async function flush(): Promise<void> {
  await new Promise((resolve) => setTimeout(resolve, 0));
}

describe('parseNotificationEvent', () => {
  it('有効なイベントを正規化する', () => {
    expect(parseNotificationEvent(ACCEPTED_EVENT)).toEqual({
      event: 'credential_accepted',
      notification_id: 'notif-1',
      notification_issued_at: '2026-07-01T00:00:00Z',
      credential_configuration_id: 'UniversityDegree',
      transaction_id: 'tx-1',
    });
  });

  it('未知の event 種別を棄却する', () => {
    expect(parseNotificationEvent({ ...ACCEPTED_EVENT, event: 'bogus' })).toBeUndefined();
  });

  it('notification_id 欠落を棄却する', () => {
    const { notification_id: _omit, ...rest } = ACCEPTED_EVENT;
    expect(parseNotificationEvent(rest)).toBeUndefined();
  });

  it('オブジェクト以外を棄却する', () => {
    expect(parseNotificationEvent(null)).toBeUndefined();
    expect(parseNotificationEvent('x')).toBeUndefined();
  });

  it('任意フィールド無しでも正規化する', () => {
    const parsed = parseNotificationEvent({
      event: 'credential_revoked',
      notification_id: 'notif-2',
      notification_issued_at: '2026-07-02T00:00:00Z',
    });
    expect(parsed?.event).toBe('credential_revoked');
    expect(parsed?.credential_configuration_id).toBeUndefined();
  });
});

describe('subscribeCredentialNotification — チャネル登録', () => {
  it('非 HTTPS の issuerURL を NOTIFICATION_ACCESS_TOKEN_INVALID で拒否する', async () => {
    await expect(
      subscribeCredentialNotification('http://issuer.example/n', 'poll', async () => {}),
    ).rejects.toMatchObject({ code: ErrorCodes.NOTIFICATION_ACCESS_TOKEN_INVALID });
  });

  it('poll モードで購読ハンドルを生成し ID とモードを持つ', async () => {
    const scheduler = manualScheduler();
    const sub = await subscribeCredentialNotification(ISSUER_URL, 'poll', async () => {}, {
      generateId: () => 'sub-poll',
      schedule: scheduler.schedule,
      fetchImpl: jsonFetch({ events: [] }),
    });
    expect(sub.id).toBe('sub-poll');
    expect(sub.mode).toBe('poll');
    expect(scheduler.intervalMs).toBe(DEFAULT_NOTIFICATION_POLL_INTERVAL_MS);
  });

  it('webhook モードで endpoint を登録し返す', async () => {
    const sub = await subscribeCredentialNotification(ISSUER_URL, 'webhook', async () => {}, {
      generateId: () => 'sub-wh',
      registerWebhook: async (_url, id) => `https://wallet.example/hook/${id}`,
    });
    expect(sub.mode).toBe('webhook');
    expect(sub.endpoint).toBe('https://wallet.example/hook/sub-wh');
    await sub.unsubscribe();
  });

  it('push モードで subscribePush が無ければ拒否する', async () => {
    await expect(
      subscribeCredentialNotification(ISSUER_URL, 'push', async () => {}),
    ).rejects.toBeInstanceOf(VericertsError);
  });

  it('unsubscribe は冪等（poll タイマーを 1 回だけ停止する）', async () => {
    const scheduler = manualScheduler();
    const sub = await subscribeCredentialNotification(ISSUER_URL, 'poll', async () => {}, {
      schedule: scheduler.schedule,
      fetchImpl: jsonFetch({ events: [] }),
    });
    await sub.unsubscribe();
    await sub.unsubscribe();
    expect(scheduler.stopped).toBe(true);
  });
});

describe('subscribeCredentialNotification — イベント処理（統合）', () => {
  it('poll ポーリングで受領したイベントを handler へ配送する', async () => {
    const received: CredentialNotificationEvent[] = [];
    const scheduler = manualScheduler();
    await subscribeCredentialNotification(
      ISSUER_URL,
      'poll',
      async (event) => {
        received.push(event);
      },
      { schedule: scheduler.schedule, fetchImpl: jsonFetch({ events: [ACCEPTED_EVENT] }) },
    );
    scheduler.fire();
    await flush();
    expect(received).toHaveLength(1);
    expect(received[0]?.event).toBe('credential_accepted');
    expect(received[0]?.notification_id).toBe('notif-1');
  });

  it('poll は GET を body なしで送る（実 fetch は GET+body で TypeError になるため）', async () => {
    // 回帰: 以前は body: '' を渡しており、実グローバル fetch では GET+body が TypeError となり
    // pollOnce の catch に握られ、イベントが一切配送されなかった。
    let capturedMethod: string | undefined;
    let capturedHasBody = true;
    const scheduler = manualScheduler();
    await subscribeCredentialNotification(ISSUER_URL, 'poll', async () => {}, {
      schedule: scheduler.schedule,
      fetchImpl: async (_input, init) => {
        capturedMethod = init.method;
        capturedHasBody = 'body' in (init as Record<string, unknown>);
        return new Response(JSON.stringify({ events: [] }), { status: 200 });
      },
    });
    scheduler.fire();
    await flush();
    expect(capturedMethod).toBe('GET');
    expect(capturedHasBody).toBe(false);
  });

  it('poll で HTTP エラー時はイベントを配送しない（次回回復を許す）', async () => {
    const received: CredentialNotificationEvent[] = [];
    const scheduler = manualScheduler();
    await subscribeCredentialNotification(
      ISSUER_URL,
      'poll',
      async (event) => {
        received.push(event);
      },
      { schedule: scheduler.schedule, fetchImpl: async () => new Response('err', { status: 500 }) },
    );
    scheduler.fire();
    await flush();
    expect(received).toHaveLength(0);
  });

  it('poll で handler が throw しても購読ループは止まらない', async () => {
    let calls = 0;
    const scheduler = manualScheduler();
    await subscribeCredentialNotification(
      ISSUER_URL,
      'poll',
      async () => {
        calls += 1;
        throw new Error('handler boom');
      },
      { schedule: scheduler.schedule, fetchImpl: jsonFetch({ events: [ACCEPTED_EVENT] }) },
    );
    scheduler.fire();
    await flush();
    scheduler.fire();
    await flush();
    expect(calls).toBe(2);
  });

  it('push モードで受信イベントを handler へ配送し unsubscribe で解除する', async () => {
    const received: CredentialNotificationEvent[] = [];
    let unsubscribed = false;
    let emit: ((e: CredentialNotificationEvent) => void) | undefined;
    const sub = await subscribeCredentialNotification(
      ISSUER_URL,
      'push',
      async (event) => {
        received.push(event);
      },
      {
        subscribePush: (onEvent) => {
          emit = onEvent;
          return () => {
            unsubscribed = true;
          };
        },
      },
    );
    emit?.(parseNotificationEvent(ACCEPTED_EVENT) as CredentialNotificationEvent);
    await flush();
    expect(received).toHaveLength(1);
    await sub.unsubscribe();
    expect(unsubscribed).toBe(true);
  });
});

describe('deliverWebhook — WebHook 受信', () => {
  it('購読済み ID の受信ペイロードを handler へ配送する', async () => {
    const received: CredentialNotificationEvent[] = [];
    const sub = await subscribeCredentialNotification(
      ISSUER_URL,
      'webhook',
      async (event) => {
        received.push(event);
      },
      { generateId: () => 'sub-deliver' },
    );
    const delivered = deliverWebhook('sub-deliver', {
      event: 'credential_revoked',
      notification_id: 'notif-9',
      notification_issued_at: '2026-07-03T00:00:00Z',
      reason: 'compromised',
    });
    await flush();
    expect(delivered).toBe(true);
    expect(received).toHaveLength(1);
    expect(received[0]?.event).toBe('credential_revoked');
    expect(received[0]?.reason).toBe('compromised');
    await sub.unsubscribe();
  });

  it('未知の購読 ID には配送せず false を返す', () => {
    expect(deliverWebhook('no-such-sub', ACCEPTED_EVENT)).toBe(false);
  });

  it('不正ペイロードは false を返し配送しない', async () => {
    const received: CredentialNotificationEvent[] = [];
    const sub = await subscribeCredentialNotification(
      ISSUER_URL,
      'webhook',
      async (event) => {
        received.push(event);
      },
      { generateId: () => 'sub-bad' },
    );
    expect(deliverWebhook('sub-bad', { event: 'nope' })).toBe(false);
    await flush();
    expect(received).toHaveLength(0);
    await sub.unsubscribe();
  });

  it('unsubscribe 後は配送されない', async () => {
    const sub = await subscribeCredentialNotification(ISSUER_URL, 'webhook', async () => {}, {
      generateId: () => 'sub-gone',
    });
    await sub.unsubscribe();
    expect(deliverWebhook('sub-gone', ACCEPTED_EVENT)).toBe(false);
  });
});
