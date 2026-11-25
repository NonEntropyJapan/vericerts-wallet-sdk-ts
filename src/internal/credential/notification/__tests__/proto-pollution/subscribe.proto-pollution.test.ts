/**
 * `subscribeCredentialNotification` の `Object.prototype` 汚染耐性テスト。
 *
 * `notification/subscribe.ts` は `own-property.js` を import すらしておらず、`SubscribeDependencies`
 * の全メンバ（`fetchImpl` / `schedule` / `intervalMs` / `registerWebhook` / `unregister` /
 * `subscribePush` / `generateId`）をプロトタイプ鎖経由の裸プロパティアクセスで読んでいた。
 *
 * `deps` を省略した正当な呼び出しが `Object.prototype` の汚染値を「指定された DI」として拾うと、
 * - `fetchImpl` 汚染: poll モードの通信が攻撃者の `fetch` 実装へ差し替わる（SSRF 相当）。
 * - `intervalMs` 汚染: ポーリング間隔が攻撃者の値になる。
 * - `schedule` / `registerWebhook` / `unregister` / `subscribePush` / `generateId` 汚染:
 *   攻撃者の関数がスケジューラ・webhook 登録・購読 ID 生成として採用される。
 *
 * 各テストは「その DI を渡していない呼び出し」が汚染値を採用しないこと、および「明示指定した
 * 呼び出し」の挙動が変わらないことの両方を固定する。データプロパティ汚染とアクセサ（getter）汚染の
 * 両方で検証する。
 */

import { describe, expect, it } from 'bun:test';
import {
  withPollutedPrototype,
  withPollutedPrototypeAccessor,
  withPollutedPrototypeAccessorAsync,
  withPollutedPrototypeAsync,
} from '../../../../__tests__/prototype-pollution.fixtures.js';
import { ErrorCodes, VericertsError } from '../../../../errors.js';
import type { FetchLike } from '../../../../fetch-di.js';
import { subscribeCredentialNotification } from '../../subscribe.js';
import { DEFAULT_NOTIFICATION_POLL_INTERVAL_MS } from '../../types.js';

const ISSUER_URL = 'https://issuer.example/notification';

function jsonFetch(body: unknown): FetchLike {
  return async () =>
    new Response(JSON.stringify(body), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    });
}

/** タスクを手動で実行できるスケジューラ。schedule DI に注入する。 */
function manualScheduler(): {
  schedule: (task: () => void, intervalMs: number) => () => void;
  fire: () => void;
  intervalMs: number | undefined;
} {
  const state = {
    task: undefined as (() => void) | undefined,
    intervalMs: undefined as number | undefined,
    schedule(task: () => void, intervalMs: number): () => void {
      state.task = task;
      state.intervalMs = intervalMs;
      return () => {};
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

describe('subscribeCredentialNotification: fetchImpl の Object.prototype 汚染耐性', () => {
  it('fetchImpl 未指定の poll 購読は汚染関数へ委譲せずグローバル fetch にフォールバックする（データ汚染）', async () => {
    const original = globalThis.fetch;
    let globalFetchCalled = false;
    globalThis.fetch = (async () => {
      globalFetchCalled = true;
      return new Response(JSON.stringify({ events: [] }), { status: 200 });
    }) as unknown as typeof fetch;
    const scheduler = manualScheduler();
    const attackerFetch: FetchLike = async () => {
      throw new Error('attacker fetch must not be called');
    };
    try {
      await withPollutedPrototypeAsync({ fetchImpl: attackerFetch }, async () => {
        const sub = await subscribeCredentialNotification(ISSUER_URL, 'poll', async () => {}, {
          schedule: scheduler.schedule,
        });
        scheduler.fire();
        await flush();
        await sub.unsubscribe();
      });
    } finally {
      globalThis.fetch = original;
    }
    expect(globalFetchCalled).toBe(true);
  });

  it('fetchImpl 未指定の poll 購読は汚染関数へ委譲しない（アクセサ汚染）', async () => {
    const original = globalThis.fetch;
    let globalFetchCalled = false;
    globalThis.fetch = (async () => {
      globalFetchCalled = true;
      return new Response(JSON.stringify({ events: [] }), { status: 200 });
    }) as unknown as typeof fetch;
    const scheduler = manualScheduler();
    try {
      await withPollutedPrototypeAccessorAsync(
        {
          fetchImpl: () => async () => {
            throw new Error('attacker fetch must not be called');
          },
        },
        async () => {
          const sub = await subscribeCredentialNotification(ISSUER_URL, 'poll', async () => {}, {
            schedule: scheduler.schedule,
          });
          scheduler.fire();
          await flush();
          await sub.unsubscribe();
        },
      );
    } finally {
      globalThis.fetch = original;
    }
    expect(globalFetchCalled).toBe(true);
  });

  it('明示指定した fetchImpl は汚染下でも指定どおり使われる（非退行）', async () => {
    const received: string[] = [];
    const scheduler = manualScheduler();
    const explicitFetch: FetchLike = async () => {
      received.push('explicit');
      return new Response(JSON.stringify({ events: [] }), { status: 200 });
    };
    const attackerFetch: FetchLike = async () => {
      throw new Error('attacker fetch must not be called');
    };
    await withPollutedPrototypeAsync({ fetchImpl: attackerFetch }, async () => {
      const sub = await subscribeCredentialNotification(ISSUER_URL, 'poll', async () => {}, {
        schedule: scheduler.schedule,
        fetchImpl: explicitFetch,
      });
      scheduler.fire();
      await flush();
      await sub.unsubscribe();
    });
    expect(received).toEqual(['explicit']);
  });
});

describe('subscribeCredentialNotification: intervalMs の Object.prototype 汚染耐性', () => {
  it('intervalMs 未指定の poll 購読は既定間隔を使う（データ汚染）', async () => {
    const scheduler = manualScheduler();
    await withPollutedPrototype({ intervalMs: 1 }, () => {
      void subscribeCredentialNotification(ISSUER_URL, 'poll', async () => {}, {
        schedule: scheduler.schedule,
        fetchImpl: jsonFetch({ events: [] }),
      });
    });
    expect(scheduler.intervalMs).toBe(DEFAULT_NOTIFICATION_POLL_INTERVAL_MS);
  });

  it('明示指定した intervalMs は汚染下でも指定どおりになる（非退行）', async () => {
    const scheduler = manualScheduler();
    await withPollutedPrototype({ intervalMs: 1 }, () => {
      void subscribeCredentialNotification(ISSUER_URL, 'poll', async () => {}, {
        schedule: scheduler.schedule,
        fetchImpl: jsonFetch({ events: [] }),
        intervalMs: 5000,
      });
    });
    expect(scheduler.intervalMs).toBe(5000);
  });
});

describe('subscribeCredentialNotification: schedule の Object.prototype 汚染耐性', () => {
  it('schedule 未指定の poll 購読は攻撃者のスケジューラへ委譲しない（データ汚染）', async () => {
    let attackerScheduleCalled = false;
    const sub = await withPollutedPrototypeAsync(
      {
        schedule: () => {
          attackerScheduleCalled = true;
          return () => {};
        },
      },
      () =>
        subscribeCredentialNotification(ISSUER_URL, 'poll', async () => {}, {
          fetchImpl: jsonFetch({ events: [] }),
        }),
    );
    await sub.unsubscribe();
    expect(attackerScheduleCalled).toBe(false);
  });
});

describe('subscribeCredentialNotification: registerWebhook / unregister の Object.prototype 汚染耐性', () => {
  it('registerWebhook 未指定の webhook 購読は issuerURL をそのまま endpoint とする（データ汚染）', async () => {
    const sub = await withPollutedPrototypeAsync(
      { registerWebhook: async () => 'https://attacker.example/hook' },
      () =>
        subscribeCredentialNotification(ISSUER_URL, 'webhook', async () => {}, {
          generateId: () => 'sub-1',
        }),
    );
    expect(sub.endpoint).toBe(ISSUER_URL);
    await sub.unsubscribe();
  });

  it('registerWebhook 未指定の webhook 購読は攻撃者関数へ委譲しない（アクセサ汚染）', async () => {
    const sub = await withPollutedPrototypeAccessorAsync(
      { registerWebhook: () => async () => 'https://attacker.example/hook' },
      () =>
        subscribeCredentialNotification(ISSUER_URL, 'webhook', async () => {}, {
          generateId: () => 'sub-2',
        }),
    );
    expect(sub.endpoint).toBe(ISSUER_URL);
    await sub.unsubscribe();
  });

  it('明示指定した registerWebhook は汚染下でも指定どおり使われる（非退行）', async () => {
    const sub = await withPollutedPrototypeAsync(
      { registerWebhook: async () => 'https://attacker.example/hook' },
      () =>
        subscribeCredentialNotification(ISSUER_URL, 'webhook', async () => {}, {
          generateId: () => 'sub-3',
          registerWebhook: async (_url, id) => `https://wallet.example/hook/${id}`,
        }),
    );
    expect(sub.endpoint).toBe('https://wallet.example/hook/sub-3');
    await sub.unsubscribe();
  });

  it('unregister 未指定の unsubscribe は攻撃者関数へ委譲しない（データ汚染）', async () => {
    let attackerUnregisterCalled = false;
    const sub = await subscribeCredentialNotification(ISSUER_URL, 'webhook', async () => {}, {
      generateId: () => 'sub-4',
    });
    await withPollutedPrototypeAsync(
      {
        unregister: async () => {
          attackerUnregisterCalled = true;
        },
      },
      () => sub.unsubscribe(),
    );
    expect(attackerUnregisterCalled).toBe(false);
  });
});

describe('subscribeCredentialNotification: subscribePush の Object.prototype 汚染耐性', () => {
  it('subscribePush 未指定の push 購読は攻撃者関数へ委譲せず拒否する（データ汚染）', async () => {
    let attackerSubscribePushCalled = false;
    await expect(
      withPollutedPrototypeAsync(
        {
          subscribePush: () => {
            attackerSubscribePushCalled = true;
            return () => {};
          },
        },
        () => subscribeCredentialNotification(ISSUER_URL, 'push', async () => {}),
      ),
    ).rejects.toBeInstanceOf(VericertsError);
    expect(attackerSubscribePushCalled).toBe(false);
  });

  it('subscribePush 未指定の push 購読は攻撃者関数へ委譲しない（アクセサ汚染）', async () => {
    let attackerSubscribePushCalled = false;
    await expect(
      withPollutedPrototypeAccessorAsync(
        {
          subscribePush: () => () => {
            attackerSubscribePushCalled = true;
            return () => {};
          },
        },
        () => subscribeCredentialNotification(ISSUER_URL, 'push', async () => {}),
      ),
    ).rejects.toMatchObject({ code: ErrorCodes.NOTIFICATION_ACCESS_TOKEN_INVALID });
    expect(attackerSubscribePushCalled).toBe(false);
  });
});

describe('subscribeCredentialNotification: generateId の Object.prototype 汚染耐性', () => {
  it('generateId 未指定の購読は攻撃者関数へ委譲せず crypto.randomUUID にフォールバックする（データ汚染）', async () => {
    const sub = await withPollutedPrototypeAsync({ generateId: () => 'attacker-id' }, () =>
      subscribeCredentialNotification(ISSUER_URL, 'webhook', async () => {}),
    );
    expect(sub.id).not.toBe('attacker-id');
    await sub.unsubscribe();
  });

  it('generateId 未指定の購読は攻撃者関数へ委譲しない（アクセサ汚染）', async () => {
    const sub = await withPollutedPrototypeAccessor({ generateId: () => () => 'attacker-id' }, () =>
      subscribeCredentialNotification(ISSUER_URL, 'webhook', async () => {}),
    );
    expect(sub.id).not.toBe('attacker-id');
    await sub.unsubscribe();
  });

  it('明示指定した generateId は汚染下でも指定どおりになる（非退行）', async () => {
    const sub = await withPollutedPrototypeAsync({ generateId: () => 'attacker-id' }, () =>
      subscribeCredentialNotification(ISSUER_URL, 'webhook', async () => {}, {
        generateId: () => 'legit-id',
      }),
    );
    expect(sub.id).toBe('legit-id');
    await sub.unsubscribe();
  });
});
