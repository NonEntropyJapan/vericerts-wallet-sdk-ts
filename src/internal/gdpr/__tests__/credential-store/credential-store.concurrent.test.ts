/**
 * CredentialStore の read-modify-write 直列化。
 *
 * - 並行 `recordPresentation` が `presentedTo` を取りこぼさない（`revokeConsent` のスコープ解決の入力）。
 * - 並行 `markDisputed` + `setProcessingRestriction` が互いのフラグを上書きしない。
 * - 並行 `recordPresentation` + `revokeConsent` が `presentedTo` を巻き戻さない。
 */

import { describe, expect, it } from 'bun:test';
import { MemoryStorage } from '../../../../storage/storage.js';
import type { VerifiableCredential } from '../../../credential/index.js';
import { createPrivateKeySigner } from '../../../credential/index.js';
import { CredentialStore } from '../../credential-store/index.js';
import { DashboardLog } from '../../dashboard-log/dashboard-log.js';

function makeVc(id: string): VerifiableCredential {
  return {
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    type: ['VerifiableCredential'],
    issuer: 'did:example:issuer',
    credentialSubject: { id: 'did:example:subject' },
    issuanceDate: '2026-01-01T00:00:00Z',
    id,
  };
}

function setup() {
  const storage = new MemoryStorage();
  const store = new CredentialStore(storage, new DashboardLog(storage));
  return { store, signer: createPrivateKeySigner(new Uint8Array(32).fill(7), 'ES256K') };
}

describe('CredentialStore 並行更新', () => {
  it('並行 recordPresentation が全ての提示先を保持する', async () => {
    const { store } = setup();
    await store.store(makeVc('vc-1'));

    await Promise.all(['rp-a', 'rp-b', 'rp-c'].map((rp) => store.recordPresentation('vc-1', rp)));

    const loaded = await store.get('vc-1');
    expect(loaded?.presentedTo?.map((e) => e.rpIdentifier).sort()).toEqual([
      'rp-a',
      'rp-b',
      'rp-c',
    ]);
  });

  it('並行 markDisputed と setProcessingRestriction が互いのフラグを上書きしない', async () => {
    const { store, signer } = setup();
    await store.store(makeVc('vc-1'));

    await Promise.all([
      store.markDisputed('vc-1', 'typo', signer),
      store.setProcessingRestriction('vc-1', true),
    ]);

    const loaded = await store.get('vc-1');
    expect(loaded?.disputed).toBe(true);
    expect(loaded?.processingRestricted).toBe(true);
  });

  it('並行 recordPresentation と revokeConsent が presentedTo を巻き戻さない', async () => {
    const { store, signer } = setup();
    await store.store(makeVc('vc-1'));
    await store.recordPresentation('vc-1', 'rp-a');

    await Promise.all([
      store.revokeConsent({ rpIdentifier: 'rp-a' }, signer),
      store.recordPresentation('vc-1', 'rp-b'),
    ]);

    const loaded = await store.get('vc-1');
    expect(loaded?.processingRestricted).toBe(true);
    expect(loaded?.presentedTo?.map((e) => e.rpIdentifier).sort()).toEqual(['rp-a', 'rp-b']);
  });
});
