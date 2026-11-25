// test/interop/lib/waltid-public-host-guard.mjs
//
// `run-waltid-protocol.mjs` が、SDK の公開ホスト検査（`isPublicHttpsUrl`）で拒否される walt.id の
// 自己参照 URL（`baseUrl` が `https://localhost:…` 等へ退行した場合）を駆動前に検出し、ペアを fail ではなく
// `skipped` にするための判定（同梱構成は FQDN を使うため、通常は該当しない）。
// 経緯は `run-waltid-protocol.mjs` の冒頭コメント。

import { isPublicHttpsUrl } from 'vericerts-wallet-sdk/common';

/** `parseAuthorizationRequest` が非公開 `response_uri` を拒否するときの `VericertsError.context.reason`。 */
export const NON_PUBLIC_RESPONSE_URI_REASON = 'non_public_response_uri';

/** `openid-credential-offer://…` が指す、SDK が取りに行く URL（by-reference の URI / by-value の `credential_issuer`）。 */
export function offerPeerUrl(offerUri) {
  const params = new URL(offerUri).searchParams;
  const byReference = params.get('credential_offer_uri');
  if (byReference !== null) return byReference;
  try {
    return JSON.parse(params.get('credential_offer') ?? 'null')?.credential_issuer;
  } catch {
    return undefined;
  }
}

/**
 * SDK の公開ホスト検査（`isPublicHttpsUrl`）が拒否するピア URL なら、`skipped` 用の理由を返す。
 * URL が無い（判定できない）場合は `undefined` を返し、通常どおり駆動して SDK 自身に判定させる。
 */
export function publicHostGuardSkipReason(peerUrl, what) {
  if (typeof peerUrl !== 'string' || isPublicHttpsUrl(peerUrl)) return undefined;
  return `loopback host is rejected by SDK public-host guard (${what}: ${new URL(peerUrl).origin})`;
}
