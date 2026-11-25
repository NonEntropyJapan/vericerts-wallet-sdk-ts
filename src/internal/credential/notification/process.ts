/**
 * OID4VCI Credential Notification Endpoint（Issuer 側）。
 * 無効なアクセストークンは `3041`（NOTIFICATION_ACCESS_TOKEN_INVALID）、
 * 不明な通知 ID は `3042`（NOTIFICATION_ID_UNKNOWN）で拒否する。
 *
 * Wallet からの発行結果応答を受理し、`notification_id` を受領 VC と紐付けて監査ログに記録する。
 * トークン検証・通知 ID 解決・監査記録は DI で外出しする。
 *
 * セキュリティ: 例外 message / context にトークン・VC 本文を含めない。
 */

import { ErrorCodes, VericertsError } from '../../errors.js';
import { nonObjectPrototypeProperty, ownProperty } from '../../prototype-safety/own-property.js';
import {
  type CredentialNotificationRequest,
  type ProcessNotificationDependencies,
  VALID_REQUEST_EVENTS,
} from './types.js';

/**
 * OID4VCI Credential Notification Endpoint を処理する。
 *
 * 手順: (1) `notification_id` / `event` の形式検証（不正なら `NOTIFICATION_ID_UNKNOWN` 3042）。
 * (2) `verifyAccessToken` でトークン検証（失敗で `NOTIFICATION_ACCESS_TOKEN_INVALID` 3041）。
 * (3) `resolveNotificationId` で通知 ID を受領 VC と紐付け（未知で 3042）。(4) 監査ログに記録。
 *
 * @throws トークン不正で 3041、通知 ID 不正 / 未知で 3042。
 */
export async function processCredentialNotification(
  req: CredentialNotificationRequest,
  accessToken: string,
  deps: ProcessNotificationDependencies,
): Promise<void> {
  // `req` は Wallet（外部）からの HTTP リクエストボディそのもの。鎖読みだと、notification_id /
  // event を持たないリクエストが Object.prototype の汚染値で構造検証を通過し、
  // resolveNotificationId / recordAudit へ攻撃者選択の ID が渡る。
  const notificationId = ownProperty<string>(req, 'notification_id');
  const event = ownProperty<CredentialNotificationRequest['event']>(req, 'event');
  const eventDescription = ownProperty<string>(req, 'event_description');
  if (
    typeof notificationId !== 'string' ||
    notificationId.length === 0 ||
    event === undefined ||
    !VALID_REQUEST_EVENTS.has(event)
  ) {
    throw new VericertsError(ErrorCodes.NOTIFICATION_ID_UNKNOWN);
  }

  // `verifyAccessToken` はアクセストークン検証そのもの。own 限定で読むと
  // `class Deps { verifyAccessToken() {} }` 形の正当な DI を「未指定」として弾いてしまうため、
  // `nonObjectPrototypeProperty` で Object.prototype 由来だけを弾く。検証手段が無ければ
  // トークン未検証のまま先へ進めない（fail-closed）。
  const verifyAccessToken = nonObjectPrototypeProperty<
    ProcessNotificationDependencies['verifyAccessToken']
  >(deps, 'verifyAccessToken');
  if (typeof verifyAccessToken !== 'function') {
    throw new VericertsError(ErrorCodes.NOTIFICATION_ACCESS_TOKEN_INVALID);
  }
  // レシーバは `deps` に束ね直す。裸で呼ぶと、従来
  // `deps.verifyAccessToken(...)` で動いていた `this` 参照つきクラス DI が壊れる。
  const tokenValid = await verifyAccessToken.call(deps, accessToken);
  if (!tokenValid) {
    throw new VericertsError(ErrorCodes.NOTIFICATION_ACCESS_TOKEN_INVALID);
  }

  // `resolveNotificationId` も同じ理由で own 限定にはできない。解決手段が無ければ通知 ID を
  // 既知とはみなさない（fail-closed）。
  const resolveNotificationId = nonObjectPrototypeProperty<
    ProcessNotificationDependencies['resolveNotificationId']
  >(deps, 'resolveNotificationId');
  const known =
    typeof resolveNotificationId === 'function'
      ? await resolveNotificationId.call(deps, notificationId)
      : false;
  if (!known) {
    throw new VericertsError(ErrorCodes.NOTIFICATION_ID_UNKNOWN);
  }

  // `recordAudit` も同様に Object.prototype 由来だけを弾く。監査記録の手段が無い場合は
  // 攻撃者の関数へ委譲せず記録をスキップする（呼び出し側の配線ミスであり、ここで独自の
  // エラーコードを新設する必要はない）。
  const recordAudit = nonObjectPrototypeProperty<ProcessNotificationDependencies['recordAudit']>(
    deps,
    'recordAudit',
  );
  if (typeof recordAudit === 'function') {
    await recordAudit.call(deps, {
      notification_id: notificationId,
      event,
      ...(eventDescription !== undefined ? { event_description: eventDescription } : {}),
    });
  }
}
