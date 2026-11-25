/**
 * Credential Notification モジュールの公開エントリ（Holder 購読 / Issuer Endpoint）。
 *
 * 実装は subscribe（Holder）/ process（Issuer）/ types に分割し、本バレルから再エクスポートする。
 */

export { processCredentialNotification } from './process.js';
export {
  deliverWebhook,
  parseNotificationEvent,
  subscribeCredentialNotification,
} from './subscribe.js';
export {
  type CredentialNotificationEvent,
  type CredentialNotificationRequest,
  DEFAULT_NOTIFICATION_POLL_INTERVAL_MS,
  type NotificationAuditEntry,
  type NotificationMode,
  type NotificationSubscription,
  type ProcessNotificationDependencies,
  type PushUnsubscribe,
  type SubscribeDependencies,
} from './types.js';
