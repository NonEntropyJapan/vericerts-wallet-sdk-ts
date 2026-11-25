/**
 * poll チャネルの `fetchImpl` DI 規律（`internal/fetch-di.ts`）の回帰テスト。
 *
 * 取り出した関数は**取り出し元をレシーバに束ね直して**呼ぶ。裸で呼ぶと
 * `class Deps { async fetchImpl() { …this… } }` のような正当な DI が `this === undefined` で
 * TypeError になり、`pollOnce` の `catch` がそれを「イベント 0 件」へ畳む。つまり**購読は
 * 例外も出さずにイベントを 1 件も配送しなくなる**ため、通常のハンドラ配送テストでは
 * 「まだイベントが来ていない」と区別が付かない。ここは配送されることまで固定する。
 *
 * 同じ規律を `schedule` については `subscribe.test.ts` が見ているが、`fetchImpl` は見ていなかった。
 */

import { describe, expect, it } from 'bun:test';
import type { FetchLike } from '../../../fetch-di.js';
import { subscribeCredentialNotification } from '../subscribe.js';
import type { CredentialNotificationEvent, SubscribeDependencies } from '../types.js';

const ISSUER_URL = 'https://issuer.example/notification';

const ACCEPTED_EVENT = {
  event: 'credential_accepted',
  notification_id: 'notif-1',
  notification_issued_at: '2026-07-01T00:00:00Z',
  credential_configuration_id: 'UniversityDegree',
};

/** 非同期配送を待つ（microtask + macrotask フラッシュ）。 */
function flush(): Promise<unknown> {
  return new Promise((resolve) => setTimeout(resolve, 0));
}

/**
 * `this` を参照する prototype メソッドとして `fetchImpl` を実装した DI（接続プールや証明書
 * ピンニングをインスタンスに持つ実装の縮図）。裸呼び出しでは `this.body` の参照が TypeError になる。
 */
class PinnedFetchDeps {
  readonly body: string;
  calls = 0;
  task: (() => void) | undefined;

  constructor(body: string) {
    this.body = body;
  }

  async fetchImpl(): Promise<Response> {
    this.calls += 1;
    return new Response(this.body, {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  schedule(task: () => void): () => void {
    this.task = task;
    return () => {
      this.task = undefined;
    };
  }
}

describe('subscribePoll の fetchImpl 呼び出し規律', () => {
  it('this 参照つきクラス DI でもイベントを配送する（レシーバを束ねて呼ぶ）', async () => {
    const deps = new PinnedFetchDeps(JSON.stringify([ACCEPTED_EVENT]));
    const received: CredentialNotificationEvent[] = [];
    const subscription = await subscribeCredentialNotification(
      ISSUER_URL,
      'poll',
      async (event) => {
        received.push(event);
      },
      deps as unknown as SubscribeDependencies,
    );

    deps.task?.();
    await flush();

    expect(deps.calls).toBe(1);
    expect(received).toHaveLength(1);
    expect(received[0]?.notification_id).toBe('notif-1');
    await subscription.unsubscribe();
  });

  it('関数でない fetchImpl は未注入として扱う（`?? fetch` の書き分けを持たない）', async () => {
    // `resolveInjectedFetch` は `typeof === 'function'` だけを注入とみなす。`null` が
    // 「注入された」側へ落ちると、レシーバを束ねたグローバル `fetch` 呼び出しになり、
    // ブラウザでは `Illegal invocation` の TypeError が幻の通信障害として現れる。
    let globalCalls = 0;
    const original = globalThis.fetch;
    globalThis.fetch = (async () => {
      globalCalls += 1;
      return new Response('[]', { status: 200, headers: { 'Content-Type': 'application/json' } });
    }) as unknown as typeof fetch;
    let task: (() => void) | undefined;
    try {
      const subscription = await subscribeCredentialNotification(
        ISSUER_URL,
        'poll',
        async () => {},
        {
          fetchImpl: null as unknown as FetchLike,
          schedule: (t: () => void) => {
            task = t;
            return () => undefined;
          },
        },
      );
      task?.();
      await flush();
      expect(globalCalls).toBe(1);
      await subscription.unsubscribe();
    } finally {
      globalThis.fetch = original;
    }
  });
});
