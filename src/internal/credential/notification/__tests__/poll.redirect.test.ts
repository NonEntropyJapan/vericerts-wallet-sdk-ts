/**
 * poll チャネルのリダイレクトは、ホップごとに公開 HTTPS へ縛って追従する。
 *
 * `redirect: 'follow'` + 事後検査だと「公開ホスト → 302 → 内部ホスト」の GET 自体が送出済みになる。
 */

import { describe, expect, it } from 'bun:test';
import { subscribeCredentialNotification } from '../subscribe.js';
import type { CredentialNotificationEvent, SubscribeDependencies } from '../types.js';

const ISSUER_URL = 'https://issuer.example/notification';

async function flush(): Promise<void> {
  for (let i = 0; i < 3; i += 1) {
    await new Promise((resolve) => setTimeout(resolve, 0));
  }
}

interface Hop {
  readonly url: string;
  readonly redirect: RequestRedirect | undefined;
}

/** 1 ティック分の poll を走らせ、fetch に渡った URL 列と配送イベントを返す。 */
async function pollOnce(
  respond: (url: string) => Response,
): Promise<{ hops: Hop[]; received: CredentialNotificationEvent[] }> {
  const hops: Hop[] = [];
  let task: (() => void) | undefined;
  const deps: SubscribeDependencies = {
    fetchImpl: (async (url: string, init?: { redirect?: RequestRedirect }) => {
      hops.push({ url, redirect: init?.redirect });
      return respond(url);
    }) as unknown as SubscribeDependencies['fetchImpl'],
    schedule: (scheduled) => {
      task = scheduled;
      return () => {
        task = undefined;
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
  task?.();
  await flush();
  await subscription.unsubscribe();
  return { hops, received };
}

const redirectTo = (location: string): Response =>
  new Response(null, { status: 302, headers: { Location: location } });

describe('subscribePoll のリダイレクト拘束', () => {
  it.each([
    'https://10.0.0.5/events',
    'https://169.254.169.254/latest',
    'http://issuer.example/events',
  ])('公開ホストから %s へ 302 されても 2 ホップ目の fetch を呼ばない', async (location) => {
    const { hops, received } = await pollOnce(() => redirectTo(location));
    expect(hops).toEqual([{ url: ISSUER_URL, redirect: 'manual' }]);
    expect(received).toEqual([]);
  });

  it('公開 HTTPS 内のリダイレクトは追従してイベントを配送する', async () => {
    const event = {
      event: 'credential_accepted',
      notification_id: 'n-1',
      notification_issued_at: '2026-07-01T00:00:00Z',
    };
    const { hops, received } = await pollOnce((url) =>
      url === ISSUER_URL
        ? redirectTo('https://cdn.example/events')
        : new Response(JSON.stringify([event]), {
            status: 200,
            headers: { 'Content-Type': 'application/json' },
          }),
    );
    expect(hops.map((hop) => hop.url)).toEqual([ISSUER_URL, 'https://cdn.example/events']);
    expect(received).toHaveLength(1);
  });
});
