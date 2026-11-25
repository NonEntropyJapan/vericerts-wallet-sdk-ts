/**
 * CredentialStore.store の再保存。同一 `vc.id` の再受領・再同期で既存レコードを無条件に
 * 上書きし、処理制限・訂正要求・提示履歴・legalHold を初期化していた回帰を防ぐ。
 */

import { describe, expect, it } from 'bun:test';
import { MemoryStorage } from '../../../../storage/storage.js';
import type { VerifiableCredential } from '../../../credential/index.js';
import { createPrivateKeySigner } from '../../../credential/index.js';
import { encodeCredentialRecord } from '../../codec.js';
import { CredentialStore } from '../../credential-store/index.js';
import { recordKey } from '../../credential-store/records.js';
import { DashboardLog } from '../../dashboard-log/dashboard-log.js';

function makeVc(id: string, name = 'before'): VerifiableCredential {
  return {
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    type: ['VerifiableCredential'],
    issuer: 'did:example:issuer',
    credentialSubject: { id: 'did:example:subject', name },
    issuanceDate: '2026-01-01T00:00:00Z',
    id,
  };
}

function setup() {
  const storage = new MemoryStorage();
  let clock = new Date('2026-07-01T00:00:00.000Z');
  const store = new CredentialStore(storage, new DashboardLog(storage), () => clock);
  return {
    storage,
    store,
    advance: (iso: string) => {
      clock = new Date(iso);
    },
    signer: createPrivateKeySigner(new Uint8Array(32).fill(7), 'ES256K'),
  };
}

describe('CredentialStore.store の再保存', () => {
  it('処理制限・訂正要求・提示履歴を保持し、listActiveCredentials に再び現れない', async () => {
    const { store, signer, advance } = setup();
    await store.store(makeVc('vc-1'));
    await store.setProcessingRestriction('vc-1', true);
    await store.markDisputed('vc-1', 'typo', signer);
    await store.recordPresentation('vc-1', 'rp-a');
    advance('2026-08-01T00:00:00.000Z');

    const record = await store.store(makeVc('vc-1', 'after'));

    expect(record.credential.credentialSubject).toMatchObject({ name: 'after' });
    expect(record.receivedAt).toBe('2026-07-01T00:00:00.000Z');
    const loaded = await store.get('vc-1');
    expect(loaded).toEqual(record);
    expect(loaded?.processingRestricted).toBe(true);
    expect(loaded?.disputed).toBe(true);
    expect(loaded?.presentedTo?.map((e) => e.rpIdentifier)).toEqual(['rp-a']);
    expect(await store.listActiveCredentials()).toEqual([]);
  });

  it('legalHold を保持する', async () => {
    const { store, storage } = setup();
    await storage.set(
      recordKey('vc-1'),
      encodeCredentialRecord({
        id: 'vc-1',
        credential: makeVc('vc-1'),
        receivedAt: '2026-07-01T00:00:00.000Z',
        legalHold: true,
      }),
    );

    await store.store(makeVc('vc-1', 'after'));

    expect((await store.get('vc-1'))?.legalHold).toBe(true);
  });

  it('並行 store と recordPresentation が提示履歴を失わない', async () => {
    const { store } = setup();
    await store.store(makeVc('vc-1'));

    await Promise.all([
      store.store(makeVc('vc-1', 'after')),
      store.recordPresentation('vc-1', 'rp-a'),
    ]);

    const loaded = await store.get('vc-1');
    expect(loaded?.presentedTo?.map((e) => e.rpIdentifier)).toEqual(['rp-a']);
  });
});
