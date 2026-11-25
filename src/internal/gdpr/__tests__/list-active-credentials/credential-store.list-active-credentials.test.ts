/**
 * CredentialStore.listActiveCredentials の単体テスト。
 * `credential-store.test.ts` から分離（linterly の行数上限対応。`setup()` / `makeVc()` を重複定義。
 * `revoke-consent-scope/` と同方針）。PresentationDefinition マッチング自体の単体テストは
 * `wallet/credential/__tests__/match-by-presentation-definition.test.ts` を参照（layer-direction
 * 制約により評価ロジックは公開API レイヤー側にある）。
 */

import { describe, expect, it } from 'bun:test';
import { MemoryStorage } from '../../../../storage/storage.js';
import type { VerifiableCredential } from '../../../credential/index.js';
import { CredentialStore } from '../../credential-store/index.js';
import { DashboardLog } from '../../dashboard-log/dashboard-log.js';

const VC_V2_CONTEXT = 'https://www.w3.org/ns/credentials/v2';

/** テスト用の最小 VC を作る。 */
function makeVc(id: string): VerifiableCredential {
  return {
    '@context': [VC_V2_CONTEXT],
    type: ['VerifiableCredential'],
    issuer: 'did:example:issuer',
    credentialSubject: { id: 'did:example:subject', name: 'Alice' },
    issuanceDate: '2026-01-01T00:00:00Z',
    id,
  };
}

/** CredentialStore と共有 storage を組み立てる。 */
function setup() {
  const storage = new MemoryStorage();
  const dashboardLog = new DashboardLog(storage);
  const store = new CredentialStore(storage, dashboardLog);
  return { store };
}

describe('CredentialStore.listActiveCredentials', () => {
  it('保持する全 VC を返す', async () => {
    const { store } = setup();
    await store.store(makeVc('vc-1'));
    await store.store(makeVc('vc-2'));

    const credentials = await store.listActiveCredentials();

    expect(credentials.map((vc) => vc.id)).toEqual(['vc-1', 'vc-2']);
  });

  it('処理制限（processingRestricted: true）がかかった VC は除外する', async () => {
    const { store } = setup();
    await store.store(makeVc('vc-1'));
    await store.store(makeVc('vc-2'));
    await store.setProcessingRestriction('vc-1', true);

    const credentials = await store.listActiveCredentials();

    expect(credentials.map((vc) => vc.id)).toEqual(['vc-2']);
  });

  it('処理制限を解除（false）すると再び含まれる', async () => {
    const { store } = setup();
    await store.store(makeVc('vc-1'));
    await store.setProcessingRestriction('vc-1', true);
    await store.setProcessingRestriction('vc-1', false);

    const credentials = await store.listActiveCredentials();

    expect(credentials.map((vc) => vc.id)).toEqual(['vc-1']);
  });

  it('保持 VC が無ければ空配列を返す', async () => {
    const { store } = setup();
    expect(await store.listActiveCredentials()).toEqual([]);
  });
});
