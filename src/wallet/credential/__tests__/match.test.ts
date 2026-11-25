/**
 * `matchCredentialsWith`（`Wallet.matchCredentials` の実処理）の
 * 単体テスト（実鍵・モック禁止）。
 *
 * - `CredentialStore` に保存済みの VC のうち要求に合致するものを返す。
 * - `processingRestricted`（GDPR Art.18 処理制限）が付いた VC は候補から除外する。
 */

import { describe, expect, it } from 'bun:test';
import type { VerifiableCredential } from '../../../internal/credential/index.js';
import { CredentialStore } from '../../../internal/gdpr/credential-store/index.js';
import { DashboardLog } from '../../../internal/gdpr/dashboard-log/dashboard-log.js';
import { MemoryStorage } from '../../../storage/storage.js';
import { matchCredentialsWith } from '../match.js';

const CLIENT_ID = 'https://verifier.example.com';
const RESPONSE_URI = 'https://verifier.example.com/callback';

/** DCQL クエリ（`credentialSubject.name` が `Bob`）を含む直接形式の requestURI。 */
function buildRequestUri(): string {
  const dcql = {
    credentials: [
      {
        id: 'degree',
        format: 'jwt_vc_json',
        claims: [{ path: ['credentialSubject', 'name'], values: ['Bob'] }],
      },
    ],
  };
  const search = new URLSearchParams({
    response_type: 'vp_token',
    client_id: CLIENT_ID,
    response_mode: 'direct_post',
    response_uri: RESPONSE_URI,
    nonce: 'n-0S6_WzA2Mj-0123456789',
    state: 'af0ifjsldkj',
    dcql_query: JSON.stringify(dcql),
  });
  return `openid4vp://?${search.toString()}`;
}

function makeVc(id: string, name: string): VerifiableCredential {
  return {
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    type: ['VerifiableCredential', 'UniversityDegree'],
    issuer: 'did:example:issuer',
    credentialSubject: { name },
    issuanceDate: '2025-01-01T00:00:00Z',
    id,
  };
}

/** storage を共有する CredentialStore を組み立てる。 */
function setup(): CredentialStore {
  const storage = new MemoryStorage();
  return new CredentialStore(storage, new DashboardLog(storage));
}

describe('matchCredentialsWith', () => {
  it('保存済み VC のうち要求に合致するものを返す', async () => {
    const credentials = setup();
    await credentials.store(makeVc('urn:vc:bob', 'Bob'));
    await credentials.store(makeVc('urn:vc:alice', 'Alice'));

    const result = await matchCredentialsWith(credentials, buildRequestUri());

    expect(result).toHaveLength(1);
    expect(result[0]?.id).toBe('urn:vc:bob');
  });

  it('processingRestricted な VC は候補から除外する（listActiveCredentials 経由の除外）', async () => {
    const credentials = setup();
    await credentials.store(makeVc('urn:vc:bob', 'Bob'));
    await credentials.setProcessingRestriction('urn:vc:bob', true);

    const result = await matchCredentialsWith(credentials, buildRequestUri());

    expect(result).toEqual([]);
  });
});
