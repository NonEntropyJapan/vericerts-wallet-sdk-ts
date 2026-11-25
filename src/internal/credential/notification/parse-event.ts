/**
 * Credential Notification イベントの検証・正規化（Holder 側）。
 *
 * poll 応答（`poll.ts`）と webhook 受信（`subscribe.ts` の `deliverWebhook`）の両方から使う共通処理。
 * どちらも `parseJsonWithoutPrototype` でパースした null-prototype なオブジェクトを読むため、
 * `Object.prototype` 汚染の影響を受けない（own-property.ts の使い分けの対象外）。
 */

import { ownProperty } from '../../prototype-safety/own-property.js';
import type { CredentialNotificationEvent } from './types.js';
import { VALID_EVENTS } from './types.js';

/**
 * 未知フィールドを含み得る生オブジェクトを `CredentialNotificationEvent` として検証・正規化する。
 * `event` が未知種別 / 必須フィールド欠落なら `undefined` を返し、呼び出し側で握りつぶす
 * （不正通知でハンドラを起動しない）。
 */
export function parseNotificationEvent(raw: unknown): CredentialNotificationEvent | undefined {
  if (typeof raw !== 'object' || raw === null) {
    return undefined;
  }
  // 通知本文は外部（Issuer）由来の JSON。欠落したキーが `Object.prototype` の汚染値で補われて
  // 「正当な通知」が組み上がらないよう、読み取りはすべて own 限定にする。
  const field = (key: string): unknown => ownProperty<unknown>(raw, key);
  const event = field('event');
  const notificationId = field('notification_id');
  const issuedAt = field('notification_issued_at');
  const configurationId = field('credential_configuration_id');
  const transactionId = field('transaction_id');
  const reason = field('reason');
  if (
    typeof event !== 'string' ||
    !VALID_EVENTS.has(event as CredentialNotificationEvent['event']) ||
    typeof notificationId !== 'string' ||
    notificationId.length === 0 ||
    typeof issuedAt !== 'string' ||
    issuedAt.length === 0
  ) {
    return undefined;
  }
  return {
    event: event as CredentialNotificationEvent['event'],
    notification_id: notificationId,
    notification_issued_at: issuedAt,
    ...(typeof configurationId === 'string'
      ? { credential_configuration_id: configurationId }
      : {}),
    ...(typeof transactionId === 'string' ? { transaction_id: transactionId } : {}),
    ...(typeof reason === 'string' ? { reason } : {}),
  };
}
