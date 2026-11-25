/**
 * CredentialStore.recordPresentation / revokeConsent({ rpIdentifier / purpose }) の単体テスト。
 *
 * `credential-store.test.ts` から分離（linterly の 1 ファイル行数上限・ディレクトリ上限対応。同じ
 * `setup()` / `makeVc()` / `testSigner()` ヘルパーを重複定義する）。
 *
 * - recordPresentation は VC メタデータの presentedTo に提示履歴を追記する（未存在 VC は VC_NOT_FOUND）。
 * - revokeConsent({ rpIdentifier }) / ({ purpose }) は presentedTo 履歴を解決して該当 VC を処理制限にする
 *   （修正前は vcId を含まないスコープが no-op だった）。複数指定時は AND 条件。
 * - presentedTo が一致しない VC は対象にならない。
 * - scope.pseudonym のみ指定時は VC レベルの処理制限を行わない（presentedTo に pseudonym を持たない
 *   設計上の既知境界）。
 */

import { describe, expect, it } from 'bun:test';
import { MemoryStorage } from '../../../../storage/storage.js';
import type { VerifiableCredential } from '../../../credential/index.js';
import { createPrivateKeySigner } from '../../../credential/index.js';
import { ErrorCodes, VericertsError } from '../../../errors.js';
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

/** 決定的な signer を作る。 */
function testSigner() {
  return createPrivateKeySigner(new Uint8Array(32).fill(7), 'ES256K');
}

/** CredentialStore と共有 storage / DashboardLog を組み立てる。 */
function setup(now?: () => Date) {
  const storage = new MemoryStorage();
  const dashboardLog = new DashboardLog(storage, now);
  const store = new CredentialStore(storage, dashboardLog, now);
  return { storage, dashboardLog, store };
}

describe('CredentialStore.recordPresentation / revokeConsent スコープ解決', () => {
  it('recordPresentation は presentedTo に提示履歴を追記する', async () => {
    const { store } = setup(() => new Date('2026-07-02T12:00:00.000Z'));
    await store.store(makeVc('vc-1'));

    await store.recordPresentation('vc-1', 'did:web:rp.example', 'kyc');

    const loaded = await store.get('vc-1');
    expect(loaded?.presentedTo).toEqual([
      {
        rpIdentifier: 'did:web:rp.example',
        purpose: 'kyc',
        presentedAt: '2026-07-02T12:00:00.000Z',
      },
    ]);
    // 既存の提示履歴は保持したまま追記する。
    await store.recordPresentation('vc-1', 'did:web:other.example');
    const reloaded = await store.get('vc-1');
    expect(reloaded?.presentedTo).toHaveLength(2);
    expect(reloaded?.presentedTo?.[1]).toEqual({
      rpIdentifier: 'did:web:other.example',
      presentedAt: '2026-07-02T12:00:00.000Z',
    });
  });

  it('未存在 VC の recordPresentation は VC_NOT_FOUND(3070)', async () => {
    const { store } = setup();
    await expect(store.recordPresentation('missing', 'did:web:rp.example')).rejects.toThrow(
      new VericertsError(ErrorCodes.VC_NOT_FOUND),
    );
  });

  it('revokeConsent({ rpIdentifier }) は presentedTo が一致する VC を処理制限にする', async () => {
    const { store } = setup(() => new Date('2026-07-02T12:00:00.000Z'));
    await store.store(makeVc('vc-1'));
    await store.store(makeVc('vc-2'));
    await store.recordPresentation('vc-1', 'did:web:rp.example', 'kyc');
    await store.recordPresentation('vc-2', 'did:web:other.example');

    await store.revokeConsent({ rpIdentifier: 'did:web:rp.example' }, testSigner());

    // 修正前は no-op だった: 該当 RP へ提示済みの vc-1 のみ処理制限される。
    expect((await store.get('vc-1'))?.processingRestricted).toBe(true);
    expect((await store.get('vc-1'))?.restrictionUpdatedAt).toBe('2026-07-02T12:00:00.000Z');
    // 別 RP へ提示した vc-2 は対象外。
    expect((await store.get('vc-2'))?.processingRestricted).toBeUndefined();
  });

  it('revokeConsent({ purpose }) は presentedTo の purpose が一致する VC を処理制限にする', async () => {
    const { store } = setup();
    await store.store(makeVc('vc-1'));
    await store.store(makeVc('vc-2'));
    await store.recordPresentation('vc-1', 'did:web:rp.example', 'kyc');
    await store.recordPresentation('vc-2', 'did:web:rp.example', 'marketing');

    await store.revokeConsent({ purpose: 'kyc' }, testSigner());

    expect((await store.get('vc-1'))?.processingRestricted).toBe(true);
    expect((await store.get('vc-2'))?.processingRestricted).toBeUndefined();
  });

  it('revokeConsent({ rpIdentifier, purpose }) は両方一致する presentedTo エントリのみ対象にする(AND)', async () => {
    const { store } = setup();
    await store.store(makeVc('vc-1'));
    await store.store(makeVc('vc-2'));
    // vc-1: 同一 RP だが purpose 不一致。vc-2: rpIdentifier・purpose とも一致。
    await store.recordPresentation('vc-1', 'did:web:rp.example', 'marketing');
    await store.recordPresentation('vc-2', 'did:web:rp.example', 'kyc');

    await store.revokeConsent({ rpIdentifier: 'did:web:rp.example', purpose: 'kyc' }, testSigner());

    expect((await store.get('vc-1'))?.processingRestricted).toBeUndefined();
    expect((await store.get('vc-2'))?.processingRestricted).toBe(true);
  });

  it('presentedTo を持たない VC は revokeConsent({ rpIdentifier }) の対象にならない', async () => {
    const { store } = setup();
    await store.store(makeVc('vc-1'));

    await store.revokeConsent({ rpIdentifier: 'did:web:rp.example' }, testSigner());

    expect((await store.get('vc-1'))?.processingRestricted).toBeUndefined();
  });

  it('scope.pseudonym のみ指定時は VC レベルの処理制限を行わない(既知の設計境界)', async () => {
    const { store, dashboardLog } = setup();
    await store.store(makeVc('vc-1'));
    await store.recordPresentation('vc-1', 'did:web:rp.example');

    await store.revokeConsent({ pseudonym: 'urn:pseudonym:abc' }, testSigner());

    // ログは記録されるが、presentedTo に pseudonym を持たないため VC は制限されない。
    expect(await dashboardLog.list()).toHaveLength(1);
    expect((await store.get('vc-1'))?.processingRestricted).toBeUndefined();
  });
});
