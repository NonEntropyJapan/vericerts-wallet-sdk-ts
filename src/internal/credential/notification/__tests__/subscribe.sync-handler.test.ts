/**
 * 通知 handler が同期 throw / 非 Promise を返しても購読が継続すること。
 *
 * 型は `Promise<void>` を返す契約だが、実行時は JS の sync handler（`undefined` 戻り）や
 * 同期 throw もありうる。`handler(event).catch` 直書きだと poll は同一バッチの残イベントを
 * 取りこぼし、webhook の `deliverWebhook` は boolean 契約に反して TypeError を投げる。
 */

import { describe, expect, it } from 'bun:test';
import type { FetchLike } from '../../../auth/oid4vci/oid4vci.js';
import { deliverWebhook, subscribeCredentialNotification } from '../subscribe.js';
import type { CredentialNotificationEvent } from '../types.js';

const ISSUER_URL = 'https://issuer.example/notification';

function event(id: string) {
  return {
    event: 'credential_revoked',
    notification_id: id,
    notification_issued_at: '2026-07-01T00:00:00Z',
    reason: 'compromised',
  };
}

const BATCH_FETCH: FetchLike = async () =>
  new Response(JSON.stringify([event('n1'), event('n2'), event('n3')]), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  });

async function flush(): Promise<void> {
  await new Promise((resolve) => setTimeout(resolve, 0));
}

/** 即時発火できる schedule DI。 */
function fireOnce(): { schedule: (task: () => void) => () => void; fire: () => void } {
  let task: (() => void) | undefined;
  return {
    schedule: (t) => {
      task = t;
      return () => undefined;
    },
    fire: () => task?.(),
  };
}

type Handler = (e: CredentialNotificationEvent) => Promise<void>;

describe('通知 dispatch: handler の同期 throw / 非 Promise 戻り', () => {
  const syncThrowing = (seen: string[]): Handler =>
    ((e: CredentialNotificationEvent) => {
      seen.push(e.notification_id);
      throw new Error('boom');
    }) as unknown as Handler;
  const syncReturningUndefined = (seen: string[]): Handler =>
    ((e: CredentialNotificationEvent) => {
      seen.push(e.notification_id);
    }) as unknown as Handler;

  it.each([
    ['同期 throw', syncThrowing],
    ['undefined を返す sync handler', syncReturningUndefined],
  ])('poll: %s でも同一バッチの全イベントが配送される', async (_name, makeHandler) => {
    const seen: string[] = [];
    const timer = fireOnce();
    const sub = await subscribeCredentialNotification(ISSUER_URL, 'poll', makeHandler(seen), {
      fetchImpl: BATCH_FETCH,
      schedule: timer.schedule,
    });
    timer.fire();
    await flush();
    expect(seen).toEqual(['n1', 'n2', 'n3']);
    await sub.unsubscribe();
  });

  it.each([
    ['同期 throw', syncThrowing],
    ['undefined を返す sync handler', syncReturningUndefined],
  ])('webhook: %s でも deliverWebhook は例外を投げず true を返す', async (_name, makeHandler) => {
    const seen: string[] = [];
    const sub = await subscribeCredentialNotification(ISSUER_URL, 'webhook', makeHandler(seen), {
      generateId: () => 'sub-sync-handler',
    });
    expect(deliverWebhook('sub-sync-handler', event('n1'))).toBe(true);
    expect(deliverWebhook('sub-sync-handler', event('n2'))).toBe(true);
    expect(seen).toEqual(['n1', 'n2']);
    await sub.unsubscribe();
  });

  it('push: 同期 throw する handler でも次のイベントを受け取れる', async () => {
    const seen: string[] = [];
    let onEvent: ((e: CredentialNotificationEvent) => void) | undefined;
    const sub = await subscribeCredentialNotification(ISSUER_URL, 'push', syncThrowing(seen), {
      subscribePush: (cb) => {
        onEvent = cb;
        return () => undefined;
      },
    });
    const e1 = { ...event('n1') } as unknown as CredentialNotificationEvent;
    const e2 = { ...event('n2') } as unknown as CredentialNotificationEvent;
    expect(() => onEvent?.(e1)).not.toThrow();
    expect(() => onEvent?.(e2)).not.toThrow();
    expect(seen).toEqual(['n1', 'n2']);
    await sub.unsubscribe();
  });
});
