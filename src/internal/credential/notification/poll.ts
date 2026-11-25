/**
 * Holder 側で `issuerURL` を一定間隔で GET し、未処理の Credential Notification を取得・正規化する。
 * ネットワークとタイマーの実装は呼び出し側から指定できる。
 *
 * セキュリティ: 例外 message / context にエンドポイント応答本文を含めない。
 */

import { type InjectedFetch, resolveInjectedFetch } from '../../fetch-di.js';
import { declaresOversizedBody, discardBody, readBodyWithinLimit } from '../../http/body-limit.js';
import { isPublicHttpsUrl } from '../../http/public-https-url.js';
import {
  bindForPublicRedirects,
  fetchFollowingPublicRedirects,
} from '../../http/public-redirect-fetch.js';
import { assertTimerIntervalMs } from '../../primitives/option-guard.js';
import { nonObjectPrototypeProperty, ownProperty } from '../../prototype-safety/own-property.js';
import { parseJsonWithoutPrototype } from '../../prototype-safety/parse-json.js';
import { parseNotificationEvent } from './parse-event.js';
import {
  type CredentialNotificationEvent,
  DEFAULT_NOTIFICATION_POLL_INTERVAL_MS,
  NOTIFICATION_REQUEST_TIMEOUT_MS,
  type NotificationSubscription,
  type SubscribeDependencies,
} from './types.js';

/** 生の JSON パース結果から通知イベント配列を取り出す（配列 / `{ events: [] }` の両形を許容）。 */
function extractRawEvents(parsed: unknown): unknown[] {
  if (Array.isArray(parsed)) {
    return parsed;
  }
  if (typeof parsed === 'object' && parsed !== null) {
    const events = (parsed as { events?: unknown }).events;
    if (Array.isArray(events)) {
      return events;
    }
  }
  return [];
}

/**
 * poll モードで Issuer notification エンドポイントを 1 回叩き、未処理イベント配列を取得する。
 *
 * HTTP エラー / 応答不正時はイベント無しとして扱い（ハンドラを起動しない）、次回ポーリングでの
 * 回復を許す。応答本文は秘密を含み得るため message に載せない。
 *
 * @param injected {@link resolveInjectedFetch} が解決した実装とレシーバの組。**関数値だけを
 *   受け取って裸で呼んではならない** — 下の `catch` が例外をイベント 0 件へ畳むため、`this` が
 *   壊れた DI の TypeError は無言のまま「イベントが来ない購読」になる。
 * @param controller 要求を中断するための controller。**呼び出し側が持つ**。
 *   ここで生成して閉じ込めると `unsubscribe` から触れず、購読解除後も実行中の要求が完走して
 *   ハンドラを呼ぶ。タイムアウトでの abort はこの controller に対して本関数が行う。
 */
async function pollOnce(
  issuerURL: string,
  injected: InjectedFetch,
  controller: AbortController,
): Promise<readonly CredentialNotificationEvent[]> {
  const { doFetch, receiver } = injected;
  // 本文の読み出しまでを 1 つのタイムアウトで覆う（`clearTimeout` は本文読了後）。ヘッダだけ先に
  // 返して本文を引き延ばす Issuer に無限に待たないため（`internal/http/fetch-json.ts` の不変条件）。
  const timer = setTimeout(() => controller.abort(), NOTIFICATION_REQUEST_TIMEOUT_MS);
  let parsed: unknown;
  // 読まずに失敗へ倒す経路でも本文を解放できるよう、`finally` から見える位置で宣言する。
  let response: Response | undefined;
  try {
    try {
      // 購読元 `issuerURL` は Issuer が選べるため、リダイレクトを**ホップごとに**公開 HTTPS へ縛って
      // 追従する（`http/public-redirect-fetch.ts`）。`follow` + 事後検査では「公開ホスト → 302 →
      // 内部ホスト」の GET 自体が送出済みになる。GET は body を持てない（WHATWG Fetch）ため
      // `body` は載せない。レシーバは取り出し元（`deps`）に束ね直す。
      response = await fetchFollowingPublicRedirects(
        bindForPublicRedirects(doFetch, receiver),
        issuerURL,
        { method: 'GET', headers: { Accept: 'application/json' }, signal: controller.signal },
      );
    } catch {
      return [];
    }

    // 最終 URL の再検査（多層防御）。ブラウザの `opaqueredirect` は上の取得で失敗に倒れる。
    if (response.url.length > 0 && !isPublicHttpsUrl(response.url)) {
      return [];
    }
    if (!response.ok) {
      return [];
    }
    // 自己申告の `content-length` で早期に落とし、実バイト数でも上限（1 MiB）で打ち切る。
    if (declaresOversizedBody(response)) {
      return [];
    }

    try {
      // 本文読み出し中のネットワークエラー / abort / 上限超過 / パース失敗はイベント 0 件へ畳む。
      const text = await readBodyWithinLimit(response);
      if (text === undefined) {
        return [];
      }
      parsed = parseJsonWithoutPrototype(text);
    } catch {
      return [];
    }
  } finally {
    clearTimeout(timer);
    // 本文を読まずに throw した経路が接続を掴んだまま残らないようにする（読了後は no-op）。
    discardBody(response);
  }

  const events: CredentialNotificationEvent[] = [];
  for (const rawEvent of extractRawEvents(parsed)) {
    const normalized = parseNotificationEvent(rawEvent);
    if (normalized !== undefined) {
      events.push(normalized);
    }
  }
  return events;
}

/** poll モードの購読を組み立てる。 */
export function subscribePoll(
  id: string,
  issuerURL: string,
  dispatch: (event: CredentialNotificationEvent) => void,
  deps: SubscribeDependencies,
): NotificationSubscription {
  // `intervalMs` は純データ。鎖読みだと、未指定の呼び出しが汚染値のポーリング間隔を拾う
  // NaN・負値・0・Infinity・タイマー上限超過は `setInterval` で約 1ms の
  // 高頻度ループになり、Issuer へ連続 GET が飛ぶため拒否する（lend の）。
  const intervalMs = assertTimerIntervalMs(
    'intervalMs',
    ownProperty<number>(deps, 'intervalMs') ?? DEFAULT_NOTIFICATION_POLL_INTERVAL_MS,
  );
  let stopped = false;
  // 実行中の要求。`unsubscribe` から abort するために巻き上げる。
  let inFlight: AbortController | undefined;
  const tick = (): void => {
    // `intervalMs` は呼び出し側指定なので、応答より短い間隔を渡されると要求が積み上がる。
    // 実行中は no-op にして 1 要求だけが走る状態を保つ。
    if (stopped || inFlight !== undefined) {
      return;
    }
    const controller = new AbortController();
    inFlight = controller;
    // `fetchImpl` は DI 関数。own 限定で読むと `class Deps { fetchImpl() {} }` 形の正当な DI を
    // 「未指定」として弾いてしまうため、Object.prototype 由来だけを弾く。関数で
    // ない値をすべて未注入として扱う判定と、レシーバを束ねるかの判断は `resolveInjectedFetch`
    // が 1 か所で持つ（`?? fetch` と書き分けると条件がずれる）。
    void pollOnce(issuerURL, resolveInjectedFetch(deps), controller)
      .then((events) => {
        // 購読解除後に届いた応答は配送しない（`unsubscribe` 後のハンドラ起動を断つ）。
        if (stopped) {
          return;
        }
        for (const event of events) {
          dispatch(event);
        }
      })
      // `dispatch` は呼び出し側 handler を起動するため同期 throw しうる。`void` に任せると
      // MV3 Service Worker では回復経路の無い `unhandledrejection` になる。
      .catch(() => {
        // ハンドラ側のエラーはポーリングを止めない。詳細ログは呼び出し側 handler の責務。
      })
      .finally(() => {
        if (inFlight === controller) {
          inFlight = undefined;
        }
      });
  };
  const schedule = nonObjectPrototypeProperty<SubscribeDependencies['schedule']>(deps, 'schedule');
  // レシーバは `deps` に束ね直す。裸で呼ぶと、従来 `deps.schedule(...)` で
  // 動いていた `this` 参照つきクラス DI（擬似タイマーの内部状態を持つ実装など）が壊れる。
  const stop =
    typeof schedule === 'function'
      ? schedule.call(deps, tick, intervalMs)
      : ((): (() => void) => {
          const handle = setInterval(tick, intervalMs);
          return () => clearInterval(handle);
        })();
  return {
    id,
    mode: 'poll',
    async unsubscribe(): Promise<void> {
      if (stopped) {
        return;
      }
      stopped = true;
      // 実行中の要求も中断する。タイマーを止めるだけでは、飛んでいる要求が完走して
      // 解除済みの購読のハンドラを呼ぶ。
      inFlight?.abort();
      inFlight = undefined;
      stop();
    },
  };
}
