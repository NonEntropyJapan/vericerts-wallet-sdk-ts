/**
 * poll チャネルの堅牢化の回帰テスト。
 *
 * ポーリングは `setInterval` で無期限に回るため、1 回のティックの欠陥がそのまま「30 秒ごとに
 * 繰り返される欠陥」になる。ここで固定するのは次の 4 点。
 *
 * - 同期 throw するハンドラでも `unhandledrejection` を起こさない（MV3 Service Worker では
 *   回復経路の無いクラッシュログになる）。
 * - リダイレクトで平文へ降格した応答は配送しない（入口の HTTPS 検証は購読時の 1 回だけ）。
 * - `unsubscribe` 後は、実行中だった要求の応答も配送しない。
 * - 応答が返るまで次のティックは要求を重ねない。
 */

import { describe, expect, it } from 'bun:test';
import { subscribeCredentialNotification } from '../subscribe.js';
import type { CredentialNotificationEvent, SubscribeDependencies } from '../types.js';

const ISSUER_URL = 'https://issuer.example/notification';

const ACCEPTED_EVENT = {
  event: 'credential_accepted',
  notification_id: 'notif-1',
  notification_issued_at: '2026-07-01T00:00:00Z',
};

/** 非同期配送を待つ（microtask + macrotask フラッシュ）。 */
async function flush(): Promise<void> {
  for (let i = 0; i < 3; i += 1) {
    await new Promise((resolve) => setTimeout(resolve, 0));
  }
}

/** JSON 応答を作る。`finalUrl` を渡すとリダイレクト後の最終 URL として見せる。 */
function jsonResponse(body: unknown, finalUrl?: string): Response {
  const response = new Response(JSON.stringify(body), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  });
  if (finalUrl !== undefined) {
    Object.defineProperty(response, 'url', { value: finalUrl });
  }
  return response;
}

/** `schedule` DI でティックを手動起動できる依存を組み立てる。 */
function makeDeps(fetchImpl: () => Promise<Response>): {
  deps: SubscribeDependencies;
  tick: () => void;
  calls: () => number;
} {
  let task: (() => void) | undefined;
  let calls = 0;
  const deps: SubscribeDependencies = {
    fetchImpl: (async () => {
      calls += 1;
      return await fetchImpl();
    }) as unknown as SubscribeDependencies['fetchImpl'],
    schedule: (scheduled) => {
      task = scheduled;
      return () => {
        task = undefined;
      };
    },
  };
  return {
    deps,
    tick: () => task?.(),
    calls: () => calls,
  };
}

describe('subscribePoll の堅牢化', () => {
  it('同期 throw するハンドラでも unhandledRejection を起こさず次のティックを続ける', async () => {
    const { deps, tick, calls } = makeDeps(async () => jsonResponse([ACCEPTED_EVENT]));
    const unhandled: unknown[] = [];
    const onUnhandled = (reason: unknown): void => {
      unhandled.push(reason);
    };
    process.on('unhandledRejection', onUnhandled);
    try {
      // 呼び出し側が同期 throw するハンドラ（`async` でない handler は珍しくない）。
      const throwingHandler = (): Promise<void> => {
        throw new Error('handler failed');
      };
      const subscription = await subscribeCredentialNotification(
        ISSUER_URL,
        'poll',
        throwingHandler,
        deps,
      );
      tick();
      await flush();
      tick();
      await flush();
      expect(unhandled).toEqual([]);
      // 失敗したティックが実行中フラグを握ったままにしない。
      expect(calls()).toBe(2);
      await subscription.unsubscribe();
    } finally {
      process.off('unhandledRejection', onUnhandled);
    }
  });

  it('リダイレクトで平文へ降格した応答は配送しない', async () => {
    const { deps, tick } = makeDeps(async () =>
      jsonResponse([ACCEPTED_EVENT], 'http://issuer.example/notification'),
    );
    const received: CredentialNotificationEvent[] = [];
    const subscription = await subscribeCredentialNotification(
      ISSUER_URL,
      'poll',
      async (event) => {
        received.push(event);
      },
      deps,
    );

    tick();
    await flush();

    expect(received).toEqual([]);
    await subscription.unsubscribe();
  });

  it('unsubscribe 後は実行中だった要求の応答を配送せず、要求を abort する', async () => {
    let release: ((response: Response) => void) | undefined;
    let scheduledTask: (() => void) | undefined;
    let aborted = false;
    const deps: SubscribeDependencies = {
      fetchImpl: ((_url: string, init?: { signal?: AbortSignal }) => {
        init?.signal?.addEventListener('abort', () => {
          aborted = true;
        });
        return new Promise<Response>((resolve) => {
          release = resolve;
        });
      }) as unknown as SubscribeDependencies['fetchImpl'],
      schedule: (scheduled) => {
        scheduledTask = scheduled;
        return () => {
          scheduledTask = undefined;
        };
      },
    };
    const received: CredentialNotificationEvent[] = [];
    const subscription = await subscribeCredentialNotification(
      ISSUER_URL,
      'poll',
      async (event) => {
        received.push(event);
      },
      deps,
    );

    scheduledTask?.();
    await subscription.unsubscribe();
    release?.(jsonResponse([ACCEPTED_EVENT]));
    await flush();

    expect(aborted).toBe(true);
    expect(received).toEqual([]);
  });

  it('応答が返るまで次のティックは要求を重ねない', async () => {
    let release: ((response: Response) => void) | undefined;
    const { deps, tick, calls } = makeDeps(
      async () =>
        await new Promise<Response>((resolve) => {
          release = resolve;
        }),
    );
    const subscription = await subscribeCredentialNotification(
      ISSUER_URL,
      'poll',
      async () => {
        // 配送内容は本テストの関心外。
      },
      deps,
    );

    tick();
    tick();
    tick();
    await flush();
    expect(calls()).toBe(1);

    release?.(jsonResponse([]));
    await flush();
    tick();
    await flush();
    expect(calls()).toBe(2);

    await subscription.unsubscribe();
  });
});
