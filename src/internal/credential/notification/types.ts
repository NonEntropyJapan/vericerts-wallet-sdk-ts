/**
 * OID4VCI Credential Notification の型定義・定数。
 *
 * 実装は subscribe（Holder）/ process（Issuer）に分割し、本ファイルへ型と定数を集約する。
 */

import type { FetchLike } from '../../fetch-di.js';

/** Credential Notification の受信モード。 */
export type NotificationMode = 'poll' | 'webhook' | 'push';

/** poll モードのデフォルトポーリング間隔（ミリ秒）。 */
export const DEFAULT_NOTIFICATION_POLL_INTERVAL_MS = 30_000;

/** poll モードの HTTP タイムアウト（ミリ秒）。発行者通信と揃えて 10 秒。 */
export const NOTIFICATION_REQUEST_TIMEOUT_MS = 10_000;

/**
 * Holder が受け取る通知イベント。
 * 発行完了・却下・失敗・更新・失効の 5 種を表す。
 */
export interface CredentialNotificationEvent {
  /** イベント種別。 */
  readonly event:
    | 'credential_accepted'
    | 'credential_denied'
    | 'credential_failure'
    | 'credential_updated'
    | 'credential_revoked';
  /** 発行時に Issuer から受領した通知 ID。 */
  readonly notification_id: string;
  /** 通知発行時刻（ISO 8601）。 */
  readonly notification_issued_at: string;
  /** 対象 credential configuration。 */
  readonly credential_configuration_id?: string;
  /** OID4VCI transaction_id。 */
  readonly transaction_id?: string;
  /** 却下 / 失敗理由。 */
  readonly reason?: string;
}

/** 有効なイベント種別集合（応答検証に使う）。 */
export const VALID_EVENTS: ReadonlySet<CredentialNotificationEvent['event']> = new Set([
  'credential_accepted',
  'credential_denied',
  'credential_failure',
  'credential_updated',
  'credential_revoked',
]);

/**
 * 購読ハンドル。
 * `unsubscribe` で poll タイマー停止 / webhook 受信解除を行う。
 */
export interface NotificationSubscription {
  /** 購読の一意 ID。 */
  readonly id: string;
  /** 受信モード。 */
  readonly mode: NotificationMode;
  /** webhook モード時に Issuer へ登録する受信エンドポイント URL。 */
  readonly endpoint?: string;
  /** 購読解除（poll タイマー停止 / webhook・push 受信解除）。冪等。 */
  unsubscribe(): Promise<void>;
}

/** push チャネルの購読解除関数。 */
export type PushUnsubscribe = () => void | Promise<void>;

/**
 * `subscribeCredentialNotification` の依存注入。モードごとに必要な依存のみ渡せばよい。
 */
export interface SubscribeDependencies {
  /** HTTP リクエストに使う `fetch` 実装（テスト注入用）。省略時はグローバル `fetch`。poll モードで使用。 */
  readonly fetchImpl?: FetchLike;
  /**
   * poll モードのポーリングをスケジュールする。省略時は `setInterval` を使う。
   * テストで擬似タイマーを注入できるよう DI 化する。戻り値はタイマー停止関数。
   */
  readonly schedule?: (task: () => void, intervalMs: number) => () => void;
  /** poll モードのポーリング間隔（ミリ秒）。既定 30 秒。1 以上 2147483647 以下の有限数に限る（範囲外は `RangeError`）。 */
  readonly intervalMs?: number;
  /**
   * webhook モードで Issuer に受信エンドポイントを登録する。登録先 URL を返す。
   * 省略時は `issuerURL` をそのまま `endpoint` として返す（外部登録なし）。
   */
  readonly registerWebhook?: (issuerURL: string, subscriptionId: string) => Promise<string>;
  /** webhook / push モードの受信解除。`unsubscribe` から呼ばれる。 */
  readonly unregister?: (subscriptionId: string) => Promise<void>;
  /** push モードで push チャネルを購読する。受信コールバックを登録し、解除関数を返す。 */
  readonly subscribePush?: (
    onEvent: (event: CredentialNotificationEvent) => void,
  ) => PushUnsubscribe;
  /** 購読 ID 生成（テスト注入用）。省略時は `crypto.randomUUID()`。 */
  readonly generateId?: () => string;
}

/**
 * Issuer Notification Endpoint が受理する Wallet からの発行結果応答。
 */
export interface CredentialNotificationRequest {
  /** 発行時に Issuer が払い出した通知 ID。 */
  readonly notification_id: string;
  /** Wallet 側の処理結果。 */
  readonly event: 'credential_accepted' | 'credential_failure' | 'credential_deleted';
  /** 補足説明（失敗理由等）。 */
  readonly event_description?: string;
}

/** Issuer 側 `processCredentialNotification` の依存注入。 */
export interface ProcessNotificationDependencies {
  /**
   * アクセストークンを検証する（`true` で有効）。期限切れ / 不一致で `false` を返すと
   * `NOTIFICATION_ACCESS_TOKEN_INVALID`（3041）となる。
   */
  readonly verifyAccessToken: (accessToken: string) => boolean | Promise<boolean>;
  /**
   * `notification_id` に紐付く受領 VC の存在を確認する（`true` で既知）。未知 / 期限切れで
   * `false` を返すと `NOTIFICATION_ID_UNKNOWN`（3042）となる。
   */
  readonly resolveNotificationId: (notificationId: string) => boolean | Promise<boolean>;
  /**
   * 監査ログへ記録する。`notification_id` と `event` を紐付けて記録する。
   * トークンや VC 本文は渡さない。
   */
  readonly recordAudit: (entry: NotificationAuditEntry) => void | Promise<void>;
}

/** 監査ログ 1 エントリ。秘密情報（トークン / VC 本文）は含めない。 */
export interface NotificationAuditEntry {
  /** 通知 ID。 */
  readonly notification_id: string;
  /** 受理したイベント種別。 */
  readonly event: CredentialNotificationRequest['event'];
  /** 補足説明（あれば）。 */
  readonly event_description?: string;
}

/** 有効な Issuer 側イベント種別集合。 */
export const VALID_REQUEST_EVENTS: ReadonlySet<CredentialNotificationRequest['event']> = new Set([
  'credential_accepted',
  'credential_failure',
  'credential_deleted',
]);
