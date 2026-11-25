/**
 * `CredentialStore.deleteCredential`（Art.17 忘れられる権利）が `presentation` エントリも消すことの
 * 回帰テスト。
 *
 * `logPresentationEvent` が書き込む payload は VC 識別子を **`credentialIds`（配列）** で持ち、直下
 * `vcId` を持たない（`presentation-log.ts` の `buildPresentationEventPayload`）。`payloadReferencesVc`
 * が直下 `vcId` と `scope.vcId` しか見ていなかった時期は、VC を削除しても「どの RP がいつ何のクレームを
 * 見たか」という第三者開示履歴だけが残っていた。Art.17 が消去の対象としているのはまさにその記録である。
 */

import { describe, expect, it } from 'bun:test';
import { MemoryStorage } from '../../../../storage/storage.js';
import type { VerifiableCredential } from '../../../credential/index.js';
import { CredentialStore } from '../../credential-store/index.js';
import { DashboardLog } from '../../dashboard-log/dashboard-log.js';
import { logPresentationEvent } from '../../presentation-log.js';
import { testSigner } from '../dashboard-log/dashboard-log-helpers.js';

/** テスト用の最小 VC を作る。 */
function makeVc(id: string): VerifiableCredential {
  return {
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    type: ['VerifiableCredential'],
    issuer: 'did:example:issuer',
    credentialSubject: { id: 'did:example:subject', name: 'Alice' },
    issuanceDate: '2026-01-01T00:00:00Z',
    id,
  };
}

/** CredentialStore と共有 storage / DashboardLog を組み立てる。 */
function setup() {
  const storage = new MemoryStorage();
  const dashboardLog = new DashboardLog(storage);
  return { dashboardLog, store: new CredentialStore(storage, dashboardLog) };
}

describe('deleteCredential と presentation エントリ（Art.17）', () => {
  it('logPresentationEvent が記録した presentation エントリも物理削除する', async () => {
    const { store, dashboardLog } = setup();
    await store.store(makeVc('vc-1'));
    await logPresentationEvent({
      log: dashboardLog,
      signer: testSigner(),
      clientId: 'https://rp.example',
      credentialIds: ['vc-1'],
      disclosedClaims: ['given_name'],
    });
    expect(await dashboardLog.list()).toHaveLength(1);

    await store.deleteCredential('vc-1', testSigner());

    expect(await store.get('vc-1')).toBeNull();
    expect(await dashboardLog.list()).toHaveLength(0);
  });

  it('他 VC を提示した presentation エントリは残す', async () => {
    const { store, dashboardLog } = setup();
    await store.store(makeVc('vc-1'));
    await store.store(makeVc('vc-2'));
    await logPresentationEvent({
      log: dashboardLog,
      signer: testSigner(),
      clientId: 'https://rp.example',
      credentialIds: ['vc-2'],
    });

    await store.deleteCredential('vc-1', testSigner());

    const remaining = await dashboardLog.list();
    expect(remaining).toHaveLength(1);
    expect((remaining[0]?.payload as { credentialIds: readonly string[] }).credentialIds).toEqual([
      'vc-2',
    ]);
  });

  it('複数 VC を提示したエントリは削除対象 VC を含めば消える', async () => {
    const { store, dashboardLog } = setup();
    await store.store(makeVc('vc-1'));
    await logPresentationEvent({
      log: dashboardLog,
      signer: testSigner(),
      clientId: 'https://rp.example',
      credentialIds: ['vc-9', 'vc-1'],
    });

    await store.deleteCredential('vc-1', testSigner());

    expect(await dashboardLog.list()).toHaveLength(0);
  });
});
