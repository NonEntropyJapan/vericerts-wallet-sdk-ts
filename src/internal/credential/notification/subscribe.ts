/**
 * OID4VCI Credential Notification の Holder 側購読。
 *
 * `poll` / `webhook` / `push` の3モードで
 * Issuer からの発行完了・失効・更新通知を受け取り、正規化した `CredentialNotificationEvent` を
 * `handler` へ配送する。ネットワーク・タイマー・push チャネルは DI で外出しし、本モジュールを純粋な
 * プロトコルロジックとして単体テスト可能にする。poll チャネルの実装は `poll.ts` に分離している。
 *
 * 例外の message / context にトークン、エンドポイントの応答本文、VC 本文を含めない。
 */

import { ErrorCodes, VericertsError } from '../../errors.js';
import { isPublicHttpsUrl } from '../../http/public-https-url.js';
import { nonObjectPrototypeProperty } from '../../prototype-safety/own-property.js';
import { parseNotificationEvent } from './parse-event.js';
import { subscribePoll } from './poll.js';
import type {
  CredentialNotificationEvent,
  NotificationMode,
  NotificationSubscription,
  SubscribeDependencies,
} from './types.js';

/** webhook モードの購読 ID → 配送関数レジストリ。`deliverWebhook` が参照する。 */
const WEBHOOK_HANDLERS = new Map<string, (event: CredentialNotificationEvent) => void>();

/** webhook モードの購読を組み立てる。 */
async function subscribeWebhook(
  id: string,
  issuerURL: string,
  dispatch: (event: CredentialNotificationEvent) => void,
  deps: SubscribeDependencies,
): Promise<NotificationSubscription> {
  // `registerWebhook` / `unregister` は DI 関数。Object.prototype 由来だけを弾く。
  const registerWebhook = nonObjectPrototypeProperty<SubscribeDependencies['registerWebhook']>(
    deps,
    'registerWebhook',
  );
  // レシーバは `deps` に束ね直す。従来 `deps.registerWebhook(...)` で
  // 動いていた `this` 参照つきクラス DI を壊さない。
  const endpoint =
    typeof registerWebhook === 'function'
      ? await registerWebhook.call(deps, issuerURL, id)
      : issuerURL;
  WEBHOOK_HANDLERS.set(id, dispatch);
  let stopped = false;
  return {
    id,
    mode: 'webhook',
    endpoint,
    async unsubscribe(): Promise<void> {
      if (stopped) {
        return;
      }
      stopped = true;
      WEBHOOK_HANDLERS.delete(id);
      const unregister = nonObjectPrototypeProperty<SubscribeDependencies['unregister']>(
        deps,
        'unregister',
      );
      if (typeof unregister === 'function') {
        await unregister.call(deps, id);
      }
    },
  };
}

/** push モードの購読を組み立てる。 */
function subscribePush(
  id: string,
  dispatch: (event: CredentialNotificationEvent) => void,
  deps: SubscribeDependencies,
): NotificationSubscription {
  // DI 関数。Object.prototype 由来だけを弾く。
  const subscribePushDep = nonObjectPrototypeProperty<SubscribeDependencies['subscribePush']>(
    deps,
    'subscribePush',
  );
  if (typeof subscribePushDep !== 'function') {
    // push チャネルの購読手段が無ければ通知を受け取れない。呼び出し側配線ミス。
    throw new VericertsError(ErrorCodes.NOTIFICATION_ACCESS_TOKEN_INVALID);
  }
  // レシーバは `deps` に束ね直す。
  const pushUnsub = subscribePushDep.call(deps, (event) => dispatch(event));
  let stopped = false;
  return {
    id,
    mode: 'push',
    async unsubscribe(): Promise<void> {
      if (stopped) {
        return;
      }
      stopped = true;
      await pushUnsub();
      const unregister = nonObjectPrototypeProperty<SubscribeDependencies['unregister']>(
        deps,
        'unregister',
      );
      if (typeof unregister === 'function') {
        await unregister.call(deps, id);
      }
    },
  };
}

/**
 * OID4VCI Credential Notification を購読する。
 *
 * - `poll`: `issuerURL` を一定間隔で GET し、未処理イベントを `handler` に配送する（`poll.ts`）。
 * - `webhook`: `registerWebhook`（DI）で受信エンドポイントを登録し、`endpoint` を返す。受信は
 *   `deliverWebhook` で行う。
 * - `push`: `subscribePush`（DI）で push チャネルを購読し、受信イベントを `handler` に配送する。
 *
 * `handler` は非同期で呼ばれ、内部で throw しても購読は継続する（1 件の失敗で全体を止めない）。
 *
 * @throws `NOTIFICATION_ACCESS_TOKEN_INVALID`（3041）: `issuerURL` が HTTPS でない場合、
 *         または `push` モードで `subscribePush` が未指定で通知を受け取れない場合。
 * @throws `RangeError`: `poll` モードで `intervalMs` が 1 以上 2147483647 以下の有限数でない場合。
 */
export async function subscribeCredentialNotification(
  issuerURL: string,
  mode: NotificationMode,
  handler: (event: CredentialNotificationEvent) => Promise<void>,
  deps: SubscribeDependencies = {},
): Promise<NotificationSubscription> {
  if (!isPublicHttpsUrl(issuerURL)) {
    // 秘匿トークンを平文で送る恐れがあるため HTTPS 以外は拒否する。
    throw new VericertsError(ErrorCodes.NOTIFICATION_ACCESS_TOKEN_INVALID);
  }

  // DI 関数。Object.prototype 由来だけを弾く。レシーバは `deps` に束ね直す。
  const generateId = nonObjectPrototypeProperty<SubscribeDependencies['generateId']>(
    deps,
    'generateId',
  );
  const id = typeof generateId === 'function' ? generateId.call(deps) : crypto.randomUUID();

  // handler を安全に呼ぶ（throw しても購読を継続する）。型は Promise を返す契約だが、実行時は
  // 同期 throw / 非 Promise（`undefined`）戻りもありうる。`handler(event).catch` と書くと同期 throw や
  // `undefined.catch` の TypeError が `dispatch` から漏れ、poll では同一バッチの残イベント
  // （`credential_revoked` 等）が欠落し、webhook では `deliverWebhook` が boolean 契約に反して
  // 例外を投げる。
  const dispatch = (event: CredentialNotificationEvent): void => {
    try {
      void Promise.resolve(handler(event)).catch(() => {
        // ハンドラ側のエラーは購読ループを止めない。詳細ログは呼び出し側 handler の責務。
      });
    } catch {
      // 同期 throw も同様に握りつぶす（後続イベントの配送を止めない）。
    }
  };

  if (mode === 'poll') {
    return subscribePoll(id, issuerURL, dispatch, deps);
  }
  if (mode === 'webhook') {
    return subscribeWebhook(id, issuerURL, dispatch, deps);
  }
  return subscribePush(id, dispatch, deps);
}

/**
 * webhook 受信ハンドラ。外部 HTTP サーバ等が受け取った通知ペイロードを、対応する購読の
 * `handler` へ配送する。ペイロードが不正 / 購読が存在しなければ `false` を返す。
 *
 * @param subscriptionId 受信 URL に紐付く購読 ID。
 * @param payload 受信した生ペイロード（JSON パース済みオブジェクト）。
 * @returns 配送できたら `true`、購読なし / ペイロード不正で `false`。
 */
export function deliverWebhook(subscriptionId: string, payload: unknown): boolean {
  const dispatch = WEBHOOK_HANDLERS.get(subscriptionId);
  if (dispatch === undefined) {
    return false;
  }
  const event = parseNotificationEvent(payload);
  if (event === undefined) {
    return false;
  }
  dispatch(event);
  return true;
}

// `index.ts` / 既存テストが `./subscribe.js` から import しているため、分離先の re-export を保つ。
export { parseNotificationEvent } from './parse-event.js';
