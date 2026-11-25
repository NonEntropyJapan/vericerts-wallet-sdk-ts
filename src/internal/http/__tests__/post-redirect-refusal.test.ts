/**
 * 秘密を含む POST が 3xx に追従しないことの回帰テスト。
 *
 * Token / Credential / PAR（OID4VCI・OID4VP）は pre-authorized_code・tx_code・code_verifier・
 * client_assertion・access_token などを本文 / ヘッダに載せる。307 / 308 に追従されると本文ごと別ホスト
 * （内部ネットワーク含む）へ再送されるため、`redirect: 'manual'` を指定し、3xx 応答は失敗にする。
 */

import { describe, expect, it } from 'bun:test';
import { baseRequest as vciParRequest } from '../../auth/oid4vci/__tests__/par/par-fixtures.js';
import { requestCredential } from '../../auth/oid4vci/oid4vci.js';
import { pushAuthorizationRequest } from '../../auth/oid4vci/par/index.js';
import { requestTokenPreAuthorized } from '../../auth/oid4vci/token/oid4vci-token.js';
import { baseRequest as vpParRequest } from '../../auth/oid4vp-par/__tests__/oid4vp-par-fixtures.js';
import { pushAuthorizationRequestForPresentation } from '../../auth/oid4vp-par/index.js';
import type { FetchLike } from '../../fetch-di.js';

interface Recorded {
  readonly redirect: RequestRedirect | undefined;
}

/** `redirect` を記録し、常に 307（ブラウザ以外の `manual` の返り方）を返す fetch スタブ。 */
function redirectingStub(seen: Recorded[]): FetchLike {
  return async (_url, init) => {
    seen.push({ redirect: init.redirect });
    return new Response(null, { status: 307, headers: { Location: 'https://10.0.0.5/steal' } });
  };
}

/** `redirect: 'manual'` が無視されて追従された（最終 URL が内部ホスト）場合を模す fetch スタブ。 */
function followedToInternalStub(): FetchLike {
  return async () => {
    const response = new Response('{}', {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    });
    Object.defineProperty(response, 'url', { value: 'https://10.0.0.5/steal' });
    return response;
  };
}

const credentialOpts = (fetchImpl: FetchLike) => ({
  credentialEndpoint: 'https://issuer.example.com/credential',
  accessToken: 'access-token-xyz',
  format: 'jwt_vc_json',
  credentialDefinition: { type: ['VerifiableCredential'] },
  proofJwt: 'eyJ0eXAiOiJvcGVuaWQ0dmNpLXByb29mK2p3dCJ9.eyJ9.sig',
  fetchImpl,
});

const tokenOpts = (fetchImpl: FetchLike) => ({ preAuthorizedCode: 'pre-auth-code', fetchImpl });

describe('秘密を含む POST は redirect: manual で送り、3xx は失敗にする', () => {
  const routes: ReadonlyArray<[string, (f: FetchLike) => Promise<unknown>]> = [
    [
      'Token Endpoint',
      (f) => requestTokenPreAuthorized('https://issuer.example.com/token', tokenOpts(f)),
    ],
    ['Credential Endpoint', (f) => requestCredential(credentialOpts(f))],
    ['OID4VCI PAR', (f) => pushAuthorizationRequest(vciParRequest(f))],
    ['OID4VP PAR', (f) => pushAuthorizationRequestForPresentation(vpParRequest(f))],
  ];

  it.each(routes)('%s: redirect=manual を指定し、307 を拒否する', async (_name, run) => {
    const seen: Recorded[] = [];
    await expect(run(redirectingStub(seen))).rejects.toMatchObject({ name: 'VericertsError' });
    expect(seen).toEqual([{ redirect: 'manual' }]);
  });

  it.each(
    routes,
  )('%s: 追従されて最終 URL が内部ホストになった応答は採用しない', async (_name, run) => {
    await expect(run(followedToInternalStub())).rejects.toMatchObject({ name: 'VericertsError' });
  });
});
