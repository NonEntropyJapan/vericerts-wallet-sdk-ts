/**
 * CredentialStore（VC レコード永続化 + GDPR メタデータ操作）の単体テスト。
 *
 * - store / get の往復（永続化の疎通）。
 * - store は vc.id 未設定を VC_SCHEMA_INVALID(3002) で拒否。
 * - markDisputed は VC メタデータに disputed:true / disputeReason / disputedAt を設定し永続化する
 *   （ストレージ更新の検証）。
 * - markDisputed は Dashboard ログに correctionRequest エントリを追記する（ログ記録の検証）。
 * - 未存在 VC の markDisputed は VC_NOT_FOUND(3070)。
 * - VC 本体の署名（credential）には影響しない（credential 内容は不変）。
 * - setProcessingRestriction は processingRestricted / restrictionUpdatedAt を設定・解除できる
 *   （Art.18、ストレージ更新の検証）。
 * - 未存在 VC の setProcessingRestriction は VC_NOT_FOUND(3070)。
 * - revokeConsent は Dashboard ログに consentRevoked を JWS 署名付きで追記する（Art.7(3)、ログ記録の検証）。
 * - revokeConsent(vcId) は当該 VC を処理制限（processingRestricted:true）にする（提示対象から除外）。
 * - vcId を含まないスコープ（rpIdentifier 等）でも consentRevoked を記録する。
 * - recordPresentation / revokeConsent({ rpIdentifier }) 等の presentedTo スコープ解決テストは
 *   `revoke-consent-scope/credential-store.revoke-consent-scope.test.ts` に分離する
 *   （linterly の 1 ファイル行数上限対応）。
 * - 空スコープの revokeConsent は GDPR_CONSENT_NOT_FOUND(10603)。
 * - scope.vcId 指定で未存在 VC の revokeConsent は VC_NOT_FOUND(3070)（ログも残さない）。
 * - deleteCredential は VC レコードと当該 VC 参照の Dashboard ログエントリを物理削除する（Art.17）。
 * - deleteCredential は削除監査記録（credentialDeleted）を別パーティションに JWS 署名付きで残す。
 * - deleteCredential は他 VC のレコード・ログエントリに影響しない。
 * - 未存在 VC の deleteCredential は VC_NOT_FOUND(3070)（監査記録も残さない）。
 * - legalHold の VC の deleteCredential は GDPR_LEGAL_OBLIGATION(10602)（何も削除しない）。
 */

import { describe, expect, it } from 'bun:test';
import { MemoryStorage } from '../../../storage/storage.js';
import type { VerifiableCredential } from '../../credential/index.js';
import { createPrivateKeySigner } from '../../credential/index.js';
import { ErrorCodes, VericertsError } from '../../errors.js';
import { encodeCredentialRecord } from '../codec.js';
import { CredentialStore } from '../credential-store/index.js';
import { DashboardLog } from '../dashboard-log/dashboard-log.js';
import type { CredentialRecord } from '../types.js';

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

describe('CredentialStore', () => {
  it('store → get の往復でレコードを永続化する', async () => {
    const { store } = setup();
    const record = await store.store(makeVc('vc-1'));
    expect(record.id).toBe('vc-1');
    expect(record.disputed).toBeUndefined();

    const loaded = await store.get('vc-1');
    expect(loaded?.id).toBe('vc-1');
    expect(loaded?.credential.issuer).toBe('did:example:issuer');
  });

  it('store は vc.id 未設定を VC_SCHEMA_INVALID(3002) で拒否する', async () => {
    const { store } = setup();
    const vc = { ...makeVc('x'), id: undefined } as VerifiableCredential;
    await expect(store.store(vc)).rejects.toThrow(new VericertsError(ErrorCodes.VC_SCHEMA_INVALID));
  });

  it('get は未存在で null を返す', async () => {
    const { store } = setup();
    expect(await store.get('missing')).toBeNull();
  });

  it('markDisputed は disputed:true / reason / disputedAt を storage に永続化する', async () => {
    const { store } = setup(() => new Date('2026-07-02T12:00:00.000Z'));
    await store.store(makeVc('vc-1'));

    await store.markDisputed('vc-1', '氏名が誤っている', testSigner());

    const loaded = await store.get('vc-1');
    expect(loaded?.disputed).toBe(true);
    expect(loaded?.disputeReason).toBe('氏名が誤っている');
    expect(loaded?.disputedAt).toBe('2026-07-02T12:00:00.000Z');
    // VC 本体は不変（署名に影響しない）。
    expect(loaded?.credential).toEqual(makeVc('vc-1'));
  });

  it('markDisputed は Dashboard ログに correctionRequest を JWS 署名付きで追記する', async () => {
    const { store, dashboardLog } = setup();
    await store.store(makeVc('vc-1'));

    await store.markDisputed('vc-1', '住所が古い', testSigner());

    const entries = await dashboardLog.list();
    expect(entries).toHaveLength(1);
    expect(entries[0]?.type).toBe('correctionRequest');
    expect(entries[0]?.payload).toEqual({ vcId: 'vc-1', reason: '住所が古い' });
    // JWS 署名（3 セグメント）が付与されている。
    expect(entries[0]?.signature.split('.')).toHaveLength(3);
  });

  it('未存在 VC の markDisputed は VC_NOT_FOUND(3070)', async () => {
    const { store, dashboardLog } = setup();
    await expect(store.markDisputed('missing', 'reason', testSigner())).rejects.toThrow(
      new VericertsError(ErrorCodes.VC_NOT_FOUND),
    );
    // ログにも記録されない（副作用なし）。
    expect(await dashboardLog.list()).toEqual([]);
  });

  it('setProcessingRestriction(true) は processingRestricted / restrictionUpdatedAt を永続化する', async () => {
    const { store } = setup(() => new Date('2026-07-02T12:00:00.000Z'));
    await store.store(makeVc('vc-1'));

    await store.setProcessingRestriction('vc-1', true);

    const loaded = await store.get('vc-1');
    expect(loaded?.processingRestricted).toBe(true);
    expect(loaded?.restrictionUpdatedAt).toBe('2026-07-02T12:00:00.000Z');
    // VC 本体は不変（署名に影響しない）。
    expect(loaded?.credential).toEqual(makeVc('vc-1'));
  });

  it('setProcessingRestriction(false) は処理制限を解除する', async () => {
    const { store } = setup();
    await store.store(makeVc('vc-1'));

    await store.setProcessingRestriction('vc-1', true);
    await store.setProcessingRestriction('vc-1', false);

    const loaded = await store.get('vc-1');
    expect(loaded?.processingRestricted).toBe(false);
    expect(typeof loaded?.restrictionUpdatedAt).toBe('string');
  });

  it('setProcessingRestriction は Dashboard ログに記録しない', async () => {
    const { store, dashboardLog } = setup();
    await store.store(makeVc('vc-1'));

    await store.setProcessingRestriction('vc-1', true);

    expect(await dashboardLog.list()).toEqual([]);
  });

  it('未存在 VC の setProcessingRestriction は VC_NOT_FOUND(3070)', async () => {
    const { store } = setup();
    await expect(store.setProcessingRestriction('missing', true)).rejects.toThrow(
      new VericertsError(ErrorCodes.VC_NOT_FOUND),
    );
  });

  it('revokeConsent(vcId) は consentRevoked を JWS 署名付きで追記し当該 VC を処理制限にする', async () => {
    const { store, dashboardLog } = setup(() => new Date('2026-07-02T12:00:00.000Z'));
    await store.store(makeVc('vc-1'));

    await store.revokeConsent({ vcId: 'vc-1' }, testSigner());

    // Dashboard ログ: consentRevoked をスコープ付きで JWS 記録。
    const entries = await dashboardLog.list();
    expect(entries).toHaveLength(1);
    expect(entries[0]?.type).toBe('consentRevoked');
    expect(entries[0]?.payload).toEqual({ scope: { vcId: 'vc-1' } });
    expect(entries[0]?.signature.split('.')).toHaveLength(3);

    // ストレージ更新: 当該 VC が処理制限（提示対象から除外）される。VC 本体は不変。
    const loaded = await store.get('vc-1');
    expect(loaded?.processingRestricted).toBe(true);
    expect(loaded?.restrictionUpdatedAt).toBe('2026-07-02T12:00:00.000Z');
    expect(loaded?.credential).toEqual(makeVc('vc-1'));
  });

  it('revokeConsent は vcId を含まないスコープ（rpIdentifier / purpose）でも consentRevoked を記録する', async () => {
    const { store, dashboardLog } = setup();

    await store.revokeConsent({ rpIdentifier: 'did:web:rp.example', purpose: 'kyc' }, testSigner());

    const entries = await dashboardLog.list();
    expect(entries).toHaveLength(1);
    expect(entries[0]?.type).toBe('consentRevoked');
    expect(entries[0]?.payload).toEqual({
      scope: { rpIdentifier: 'did:web:rp.example', purpose: 'kyc' },
    });
  });

  it('空スコープの revokeConsent は GDPR_CONSENT_NOT_FOUND(10603)（ログも残さない）', async () => {
    const { store, dashboardLog } = setup();
    await expect(store.revokeConsent({}, testSigner())).rejects.toThrow(
      new VericertsError(ErrorCodes.GDPR_CONSENT_NOT_FOUND),
    );
    expect(await dashboardLog.list()).toEqual([]);
  });

  it('scope.vcId 指定で未存在 VC の revokeConsent は VC_NOT_FOUND(3070)（ログも残さない）', async () => {
    const { store, dashboardLog } = setup();
    await expect(store.revokeConsent({ vcId: 'missing' }, testSigner())).rejects.toThrow(
      new VericertsError(ErrorCodes.VC_NOT_FOUND),
    );
    expect(await dashboardLog.list()).toEqual([]);
  });

  it('deleteCredential は VC レコードと当該 VC 参照の Dashboard ログエントリを物理削除する（Art.17）', async () => {
    const { store, dashboardLog, storage } = setup();
    await store.store(makeVc('vc-1'));
    // vc-1 を参照する Dashboard ログエントリを 2 件作る。
    await store.markDisputed('vc-1', '氏名誤り', testSigner());
    await store.revokeConsent({ vcId: 'vc-1' }, testSigner());
    expect(await dashboardLog.list()).toHaveLength(2);

    await store.deleteCredential('vc-1', testSigner());

    // VC レコード本体が物理削除される。
    expect(await store.get('vc-1')).toBeNull();
    expect(await storage.get('credential/vc-1')).toBeNull();
    // vc-1 を参照するユーザー制御 Dashboard ログエントリが物理削除される。
    expect(await dashboardLog.list()).toHaveLength(0);
  });

  it('deleteCredential は削除監査記録（credentialDeleted）を別パーティションに JWS 署名付きで残す', async () => {
    const { store, dashboardLog } = setup();
    await store.store(makeVc('vc-1'));

    await store.deleteCredential('vc-1', testSigner());

    // ユーザー制御ログ（dashboard-log/）には残らない。
    expect(await dashboardLog.list()).toHaveLength(0);
    // 削除監査記録（deletion-log/）に credentialDeleted が JWS 署名付きで残る。
    const records = await dashboardLog.listDeletionRecords();
    expect(records).toHaveLength(1);
    expect(records[0]?.type).toBe('credentialDeleted');
    expect(records[0]?.payload).toEqual({ vcId: 'vc-1' });
    expect(records[0]?.signature.split('.')).toHaveLength(3);
  });

  it('deleteCredential は他 VC のレコード・ログエントリに影響しない', async () => {
    const { store, dashboardLog } = setup();
    await store.store(makeVc('vc-1'));
    await store.store(makeVc('vc-2'));
    await store.markDisputed('vc-1', '誤り1', testSigner());
    await store.markDisputed('vc-2', '誤り2', testSigner());

    await store.deleteCredential('vc-1', testSigner());

    // vc-2 のレコードは残る。
    expect((await store.get('vc-2'))?.id).toBe('vc-2');
    // vc-2 を参照する Dashboard ログエントリは残る（vc-1 の分のみ削除）。
    const entries = await dashboardLog.list();
    expect(entries).toHaveLength(1);
    expect(entries[0]?.payload).toEqual({ vcId: 'vc-2', reason: '誤り2' });
  });

  it('未存在 VC の deleteCredential は VC_NOT_FOUND(3070)（監査記録も残さない）', async () => {
    const { store, dashboardLog } = setup();
    await expect(store.deleteCredential('missing', testSigner())).rejects.toThrow(
      new VericertsError(ErrorCodes.VC_NOT_FOUND),
    );
    expect(await dashboardLog.listDeletionRecords()).toEqual([]);
  });

  it('legalHold の VC の deleteCredential は GDPR_LEGAL_OBLIGATION(10602)（何も削除しない）', async () => {
    const { store, dashboardLog, storage } = setup();
    // 法的保持中の VC レコードを storage に直接永続化する（store() は legalHold を設定しないため）。
    const held: CredentialRecord = {
      id: 'vc-held',
      credential: makeVc('vc-held'),
      receivedAt: '2026-07-02T12:00:00.000Z',
      legalHold: true,
    };
    await storage.set('credential/vc-held', encodeCredentialRecord(held));

    await expect(store.deleteCredential('vc-held', testSigner())).rejects.toThrow(
      new VericertsError(ErrorCodes.GDPR_LEGAL_OBLIGATION),
    );

    // 何も削除されない・監査記録も残さない。
    expect((await store.get('vc-held'))?.id).toBe('vc-held');
    expect(await dashboardLog.listDeletionRecords()).toEqual([]);
  });
});
