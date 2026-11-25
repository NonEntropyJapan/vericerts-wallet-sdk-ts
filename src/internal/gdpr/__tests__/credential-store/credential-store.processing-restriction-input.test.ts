/**
 * CredentialStore.setProcessingRestriction の入力検査。`listActiveCredentials` は
 * `=== true` のときだけ除外するため、`'true'` / `1` を永続化すると成功扱いのまま Art.18 処理制限が
 * 効かない（権利行使の fail-open）。boolean 以外は永続化の前に 3002 で拒否する。
 */

import { describe, expect, it } from 'bun:test';
import { MemoryStorage } from '../../../../storage/storage.js';
import type { VerifiableCredential } from '../../../credential/index.js';
import { ErrorCodes, VericertsError } from '../../../errors.js';
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

describe('CredentialStore.setProcessingRestriction の入力検査', () => {
  it.each([
    ['true'],
    [1],
    [0],
    [undefined],
    [null],
  ])('boolean 以外（%p）は 3002 で拒否し、レコードを変えない', async (value) => {
    const storage = new MemoryStorage();
    const store = new CredentialStore(storage, new DashboardLog(storage));
    await store.store(makeVc('vc-1'));
    const before = await store.get('vc-1');

    await expect(
      store.setProcessingRestriction('vc-1', value as unknown as boolean),
    ).rejects.toThrow(new VericertsError(ErrorCodes.VC_SCHEMA_INVALID));
    expect(await store.get('vc-1')).toEqual(before);
    expect((await store.listActiveCredentials()).map((vc) => vc.id)).toEqual(['vc-1']);
  });

  it('boolean（true / false）は従来どおり反映される', async () => {
    const storage = new MemoryStorage();
    const store = new CredentialStore(storage, new DashboardLog(storage));
    await store.store(makeVc('vc-1'));

    await store.setProcessingRestriction('vc-1', true);
    expect(await store.listActiveCredentials()).toEqual([]);

    await store.setProcessingRestriction('vc-1', false);
    expect((await store.listActiveCredentials()).map((vc) => vc.id)).toEqual(['vc-1']);
  });
});
