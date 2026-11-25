// test/interop/lib/waltid-verifier-session.mjs
//
// walt.id verifier-api への Authorization Request 発行要求とセッション状態のポーリング（→ Present）。
// `run-waltid-protocol.mjs` を Linterly の 1 ファイル 300 行上限に収めるため切り出した。

import { FORMAT_JWT_VC } from 'vericerts-wallet-sdk';
import { CREDENTIAL_TYPE, fetchJson, verifierAdminBaseUrl } from './waltid-admin-api.mjs';

/** walt.id verifier-api に Authorization Request 発行を要求する（管理系呼び出し。§3.2 手順 3）。 */
export async function createVerifierRequest(fetchImpl = fetch) {
  const adminBaseUrl = verifierAdminBaseUrl();
  const { ok, body } = await fetchJson(
    `${adminBaseUrl}/openid4vc/verify`,
    {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        request_credentials: [{ format: FORMAT_JWT_VC, type: CREDENTIAL_TYPE }],
      }),
    },
    fetchImpl,
  );
  if (!ok || typeof body !== 'string' || !body.startsWith('openid4vp://')) {
    throw new Error(`waltid-verifier request creation failed: ${JSON.stringify(body)}`);
  }
  return body;
}

/** walt.id verifier-api のセッション状態から提示の検証結果を確認する（§3.2 手順 4 の確認）。 */
export async function pollVerifierSession(
  requestUri,
  { fetchImpl = fetch, maxAttempts = 10, intervalMs = 500 } = {},
) {
  const adminBaseUrl = verifierAdminBaseUrl();
  const state = new URL(requestUri).searchParams.get('state');
  for (let attempt = 0; attempt < maxAttempts; attempt += 1) {
    const { ok, body } = await fetchJson(
      `${adminBaseUrl}/openid4vc/session/${state}`,
      undefined,
      fetchImpl,
    );
    if (ok && body?.verificationResult === true) {
      return { verified: true };
    }
    if (ok && body?.verificationResult === false) {
      return { verified: false, reason: JSON.stringify(body?.policyResults ?? body) };
    }
    await new Promise((resolve) => setTimeout(resolve, intervalMs));
  }
  return { verified: false, reason: 'verifier session did not report a result in time' };
}

/**
 * Authorization Request URI の `presentation_definition_uri`（by-reference の Presentation Definition）を
 * 取得して返す。walt.id verifier は定義を URI 参照で告知する（`presentation_definition` は載せない）。
 * SDK の同期パーサ（`parseAuthorizationRequest`）は参照を解決しないため、Holder 役のドライバが取得して
 * `request.presentationDefinition` に載せ、`submitPresentation` が `presentation_submission` を構築できるようにする。
 * 参照が無い URI では `undefined`。
 */
export async function fetchPresentationDefinition(requestUri, fetchImpl = fetch) {
  const definitionUri = new URL(requestUri).searchParams.get('presentation_definition_uri');
  if (definitionUri === null) {
    return undefined;
  }
  const { ok, body } = await fetchJson(definitionUri, undefined, fetchImpl);
  if (!ok || typeof body !== 'object' || body === null || typeof body.id !== 'string') {
    throw new Error(
      `waltid-verifier presentation definition fetch failed: ${JSON.stringify(body)}`,
    );
  }
  return body;
}
