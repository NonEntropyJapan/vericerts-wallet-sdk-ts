/**
 * OID4VCI の Offer / Issuer Metadata が運ぶ、攻撃者が件数と長さを選べる値の上限。
 *
 * Offer（`credential_offer_uri` 先）も Issuer Metadata も本文は 1 MiB まで受け入れるため、
 * 件数だけ・長さだけの上限では、もう一方の軸を最大にした積で CPU を占有できる（Offer の id 件数 ×
 * Metadata の `type` 長、`authorization_server` の末尾スラッシュ長 × `authorization_servers` 件数）。
 * 正規の Offer / Metadata は id 数個・AS 数個・URL 数百文字なので、いずれも十分な余裕を持たせた固定値。
 * 判定は `primitives/bounded-input.ts`（件数・1 要素長・合計長 + 共有の走査予算）で行う。
 */

import type { StringListLimits } from './bounded-input.js';

/** Offer の `credential_configuration_ids`（重複排除前の件数で課す。超過は `OFFER_URI_PARSE_FAILED`）。 */
export const CREDENTIAL_CONFIGURATION_ID_LIMITS: StringListLimits = {
  maxCount: 64,
  maxItemLength: 512,
  maxTotalLength: 16 * 1024,
};

/** `credential_definition.type`（Metadata 由来。超過は「解決できない」として未収載にする）。 */
export const CREDENTIAL_DEFINITION_TYPE_LIMITS: StringListLimits = {
  maxCount: 64,
  maxItemLength: 512,
  maxTotalLength: 16 * 1024,
};

/** Metadata の `authorization_servers`（超過は `ISSUER_COMMUNICATION_FAILED`）。 */
export const AUTHORIZATION_SERVERS_LIMITS: StringListLimits = {
  maxCount: 16,
  maxItemLength: 2048,
  maxTotalLength: 16 * 2048,
};

/** `authorization_server` 1 件（URL）の長さの上限。`AUTHORIZATION_SERVERS_LIMITS.maxItemLength` と同じ。 */
export const MAX_AUTHORIZATION_SERVER_LENGTH = AUTHORIZATION_SERVERS_LIMITS.maxItemLength;

/**
 * 1 回の Metadata 解決で `credential_definition.type` の要素を走査してよい総数。
 * id 件数（≤ 64）× type 長（≤ 64）の理論上限と同じで、id・type の上限が将来ずれても積が増えない安全弁。
 */
export const MAX_METADATA_TYPE_SCAN_UNITS =
  CREDENTIAL_CONFIGURATION_ID_LIMITS.maxCount * CREDENTIAL_DEFINITION_TYPE_LIMITS.maxCount;

/** Offer の grant が運ぶ `authorization_server` として妥当か（非空文字列かつ {@link MAX_AUTHORIZATION_SERVER_LENGTH} 以内）。 */
export function isAuthorizationServerValue(value: unknown): value is string {
  return (
    typeof value === 'string' && value.length > 0 && value.length <= MAX_AUTHORIZATION_SERVER_LENGTH
  );
}
