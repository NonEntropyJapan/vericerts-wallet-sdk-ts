/**
 * Wallet ファサードの GDPR（markCredentialDisputed / setCredentialProcessingRestriction）統合テスト。
 *
 * createWallet が storeCredential / getCredentialRecord / markCredentialDisputed /
 * setCredentialProcessingRestriction を CredentialStore / DashboardLog へ薄く委譲していることを、
 * createWallet 経由（実 storage / 実鍵）で検証する。
 * - storeCredential → getCredentialRecord 往復（永続化の疎通）。
 * - markCredentialDisputed で disputed:true が永続化される（ストレージ更新）。
 * - markCredentialDisputed が Dashboard ログに correctionRequest を記録する（ログ記録の統合）。
 * - setCredentialProcessingRestriction で processingRestricted の設定・解除が永続化される（Art.18）。
 * - setCredentialProcessingRestriction は Dashboard ログに記録しない。
 * - revokeConsent は consentRevoked を Dashboard ログに記録し vcId スコープの VC を処理制限にする（Art.7(3)）。
 * - recordPresentation / revokeConsent の rpIdentifier スコープ解決・Pseudonym 破棄の統合テストは
 *   `wallet.gdpr-revoke-consent-scope.test.ts` に分離する。
 * - 空スコープの revokeConsent → GDPR_CONSENT_NOT_FOUND(10603)。
 * - 未存在 VC → VC_NOT_FOUND(3070)。
 * - アクティブペルソナ未設定 → PERSONA_NOT_FOUND(2005)。
 * - deleteCredential は VC レコードと参照 Dashboard ログを物理削除し、削除監査記録を残す（Art.17）。
 * - 未存在 VC の deleteCredential → VC_NOT_FOUND(3070)。
 * - アクティブペルソナ未設定の deleteCredential → PERSONA_NOT_FOUND(2005)。
 * - purgeDashboardLog はユーザー制御 Dashboard ログを filter で一括削除して件数を返し、削除監査記録は
 *   残す。署名不要のためアクティブペルソナ未設定でも動作する（GDPR Art.17 削除権）。
 *
 * `exportDashboardLog` の統合テストは `wallet.gdpr-export.test.ts` に分離する。
 */

import { describe, expect, it } from 'bun:test';
import type { VerifiableCredential } from '../../../internal/credential/index.js';
import { ErrorCodes, VericertsError } from '../../../internal/errors.js';
import { decodeDashboardLogEntry } from '../../../internal/gdpr/codec.js';
import { MemoryStorage } from '../../../storage/storage.js';
import { createWallet } from '../../factory.js';
import type { Wallet } from '../../types.js';

const TEST_MNEMONIC =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const VC_V2_CONTEXT = 'https://www.w3.org/ns/credentials/v2';

/** import + アクティブペルソナ設定済みの Wallet と共有 storage を用意する。 */
async function setup(): Promise<{ wallet: Wallet; storage: MemoryStorage }> {
  const storage = new MemoryStorage();
  const wallet = await createWallet({ storage });
  await wallet.importMnemonic(TEST_MNEMONIC);
  const persona = await wallet.createPersona();
  await wallet.setActivePersona(persona.id);
  return { wallet, storage };
}

/** storage から指定パーティションのログエントリを追記順で読み出す。 */
async function readLogPartition(storage: MemoryStorage, prefix: string) {
  const keys = (await storage.list(prefix)).sort();
  const entries = [];
  for (const key of keys) {
    const bytes = await storage.get(key);
    if (bytes !== null) {
      entries.push(decodeDashboardLogEntry(bytes));
    }
  }
  return entries;
}

/** storage からユーザー制御 Dashboard ログエントリを追記順で読み出す。 */
async function readDashboardLog(storage: MemoryStorage) {
  return readLogPartition(storage, 'dashboard-log/');
}

/** テスト用の最小 VC。 */
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

describe('Wallet GDPR markCredentialDisputed', () => {
  it('storeCredential → getCredentialRecord 往復で永続化される', async () => {
    const { wallet } = await setup();
    const record = await wallet.storeCredential(makeVc('vc-1'));
    expect(record.id).toBe('vc-1');
    expect(record.disputed).toBeUndefined();

    const loaded = await wallet.getCredentialRecord('vc-1');
    expect(loaded?.id).toBe('vc-1');
    expect(loaded?.credential.issuer).toBe('did:example:issuer');
  });

  it('markCredentialDisputed は disputed:true / reason を永続化する', async () => {
    const { wallet } = await setup();
    await wallet.storeCredential(makeVc('vc-1'));

    await wallet.markCredentialDisputed('vc-1', '氏名が誤っている');

    const loaded = await wallet.getCredentialRecord('vc-1');
    expect(loaded?.disputed).toBe(true);
    expect(loaded?.disputeReason).toBe('氏名が誤っている');
    expect(typeof loaded?.disputedAt).toBe('string');
    // VC 本体は不変。
    expect(loaded?.credential).toEqual(makeVc('vc-1'));
  });

  it('markCredentialDisputed は Dashboard ログに correctionRequest を記録する（統合）', async () => {
    const { wallet, storage } = await setup();
    await wallet.storeCredential(makeVc('vc-1'));

    await wallet.markCredentialDisputed('vc-1', '住所が古い');

    const entries = await readDashboardLog(storage);
    expect(entries).toHaveLength(1);
    expect(entries[0]?.type).toBe('correctionRequest');
    expect(entries[0]?.payload).toEqual({ vcId: 'vc-1', reason: '住所が古い' });
    // アクティブペルソナ鍵で JWS 署名されている（3 セグメント）。
    expect(entries[0]?.signature.split('.')).toHaveLength(3);
    expect(entries[0]?.prevHash).toBeNull();
  });

  it('未存在 VC の markCredentialDisputed は VC_NOT_FOUND(3070)', async () => {
    const { wallet } = await setup();
    await expect(wallet.markCredentialDisputed('missing', 'reason')).rejects.toThrow(
      new VericertsError(ErrorCodes.VC_NOT_FOUND),
    );
  });

  it('setCredentialProcessingRestriction は processingRestricted を永続化・解除できる', async () => {
    const { wallet } = await setup();
    await wallet.storeCredential(makeVc('vc-1'));

    await wallet.setCredentialProcessingRestriction('vc-1', true);
    let loaded = await wallet.getCredentialRecord('vc-1');
    expect(loaded?.processingRestricted).toBe(true);
    expect(typeof loaded?.restrictionUpdatedAt).toBe('string');
    // VC 本体は不変。
    expect(loaded?.credential).toEqual(makeVc('vc-1'));

    await wallet.setCredentialProcessingRestriction('vc-1', false);
    loaded = await wallet.getCredentialRecord('vc-1');
    expect(loaded?.processingRestricted).toBe(false);
  });

  it('setCredentialProcessingRestriction は Dashboard ログに記録しない', async () => {
    const { wallet, storage } = await setup();
    await wallet.storeCredential(makeVc('vc-1'));

    await wallet.setCredentialProcessingRestriction('vc-1', true);

    expect(await readDashboardLog(storage)).toHaveLength(0);
  });

  it('未存在 VC の setCredentialProcessingRestriction は VC_NOT_FOUND(3070)', async () => {
    const { wallet } = await setup();
    await expect(wallet.setCredentialProcessingRestriction('missing', true)).rejects.toThrow(
      new VericertsError(ErrorCodes.VC_NOT_FOUND),
    );
  });

  it('アクティブペルソナ未設定で markCredentialDisputed は PERSONA_NOT_FOUND(2005)', async () => {
    const wallet = await createWallet({ storage: new MemoryStorage() });
    await wallet.importMnemonic(TEST_MNEMONIC);
    await wallet.storeCredential(makeVc('vc-1'));
    await expect(wallet.markCredentialDisputed('vc-1', 'reason')).rejects.toThrow(
      new VericertsError(ErrorCodes.PERSONA_NOT_FOUND),
    );
  });

  it('revokeConsent(vcId) は consentRevoked を記録し当該 VC を処理制限にする（統合）', async () => {
    const { wallet, storage } = await setup();
    await wallet.storeCredential(makeVc('vc-1'));

    await wallet.revokeConsent({ vcId: 'vc-1' });

    // ストレージ更新: 提示対象から除外される。
    const loaded = await wallet.getCredentialRecord('vc-1');
    expect(loaded?.processingRestricted).toBe(true);
    expect(typeof loaded?.restrictionUpdatedAt).toBe('string');
    expect(loaded?.credential).toEqual(makeVc('vc-1'));

    // ログ記録の統合: consentRevoked をスコープ付き JWS 署名で記録。
    const entries = await readDashboardLog(storage);
    expect(entries).toHaveLength(1);
    expect(entries[0]?.type).toBe('consentRevoked');
    expect(entries[0]?.payload).toEqual({ scope: { vcId: 'vc-1' } });
    expect(entries[0]?.signature.split('.')).toHaveLength(3);
  });

  it('revokeConsent は rpIdentifier スコープでも consentRevoked を記録する（vcId なし）', async () => {
    const { wallet, storage } = await setup();

    await wallet.revokeConsent({ rpIdentifier: 'did:web:rp.example' });

    const entries = await readDashboardLog(storage);
    expect(entries).toHaveLength(1);
    expect(entries[0]?.type).toBe('consentRevoked');
    expect(entries[0]?.payload).toEqual({ scope: { rpIdentifier: 'did:web:rp.example' } });
  });

  it('空スコープの revokeConsent は GDPR_CONSENT_NOT_FOUND(10603)', async () => {
    const { wallet } = await setup();
    await expect(wallet.revokeConsent({})).rejects.toThrow(
      new VericertsError(ErrorCodes.GDPR_CONSENT_NOT_FOUND),
    );
  });

  it('scope.vcId 指定で未存在 VC の revokeConsent は VC_NOT_FOUND(3070)', async () => {
    const { wallet } = await setup();
    await expect(wallet.revokeConsent({ vcId: 'missing' })).rejects.toThrow(
      new VericertsError(ErrorCodes.VC_NOT_FOUND),
    );
  });

  it('アクティブペルソナ未設定で revokeConsent は PERSONA_NOT_FOUND(2005)', async () => {
    const wallet = await createWallet({ storage: new MemoryStorage() });
    await wallet.importMnemonic(TEST_MNEMONIC);
    await wallet.storeCredential(makeVc('vc-1'));
    await expect(wallet.revokeConsent({ vcId: 'vc-1' })).rejects.toThrow(
      new VericertsError(ErrorCodes.PERSONA_NOT_FOUND),
    );
  });

  it('deleteCredential は VC レコードと参照ログを物理削除し削除監査記録を残す（統合、Art.17）', async () => {
    const { wallet, storage } = await setup();
    await wallet.storeCredential(makeVc('vc-1'));
    await wallet.markCredentialDisputed('vc-1', '氏名誤り');
    expect(await readDashboardLog(storage)).toHaveLength(1);

    await wallet.deleteCredential('vc-1');

    // ストレージ更新: VC レコード本体が物理削除される。
    expect(await wallet.getCredentialRecord('vc-1')).toBeNull();
    // ユーザー制御 Dashboard ログの vc-1 参照エントリが物理削除される。
    expect(await readDashboardLog(storage)).toHaveLength(0);
    // ログ記録の統合: 削除監査記録（credentialDeleted）が別パーティションに JWS 署名付きで残る。
    // 参照ログの物理削除が chain に空ける穴の説明（logEntryDeleted）も同じパーティションに残る。
    const records = await readLogPartition(storage, 'deletion-log/');
    expect(records.map((r) => r.type)).toEqual(['credentialDeleted', 'logEntryDeleted']);
    expect(records[0]?.payload).toEqual({ vcId: 'vc-1' });
    expect(records[0]?.signature.split('.')).toHaveLength(3);
  });

  it('未存在 VC の deleteCredential は VC_NOT_FOUND(3070)', async () => {
    const { wallet } = await setup();
    await expect(wallet.deleteCredential('missing')).rejects.toThrow(
      new VericertsError(ErrorCodes.VC_NOT_FOUND),
    );
  });

  it('アクティブペルソナ未設定で deleteCredential は PERSONA_NOT_FOUND(2005)', async () => {
    const wallet = await createWallet({ storage: new MemoryStorage() });
    await wallet.importMnemonic(TEST_MNEMONIC);
    await wallet.storeCredential(makeVc('vc-1'));
    await expect(wallet.deleteCredential('vc-1')).rejects.toThrow(
      new VericertsError(ErrorCodes.PERSONA_NOT_FOUND),
    );
  });
});

describe('Wallet GDPR purgeDashboardLog', () => {
  it('filter なしでユーザー制御 Dashboard ログを全削除し件数を返す（ストレージ更新）', async () => {
    const { wallet, storage } = await setup();
    await wallet.storeCredential(makeVc('vc-1'));
    await wallet.markCredentialDisputed('vc-1', '氏名誤り');
    await wallet.revokeConsent({ rpIdentifier: 'did:web:rp.example' });
    // 事前状態: correctionRequest + consentRevoked の 2 件が記録されている。
    expect(await readDashboardLog(storage)).toHaveLength(2);

    const deleted = await wallet.purgeDashboardLog();

    // 戻り値: 削除件数。
    expect(deleted).toBe(2);
    // ストレージ更新: ユーザー制御 Dashboard ログが空になる。
    expect(await readDashboardLog(storage)).toHaveLength(0);
  });

  it('types フィルタで指定種別のみ削除し、削除監査記録は残す', async () => {
    const { wallet, storage } = await setup();
    await wallet.storeCredential(makeVc('vc-1'));
    await wallet.markCredentialDisputed('vc-1', '氏名誤り');
    await wallet.revokeConsent({ rpIdentifier: 'did:web:rp.example' });
    // deleteCredential で deletion-log/ に監査記録を作る（purge 対象外であることの検証用）。
    await wallet.storeCredential(makeVc('vc-2'));
    await wallet.deleteCredential('vc-2');

    const deleted = await wallet.purgeDashboardLog({ types: ['correctionRequest'] });

    expect(deleted).toBe(1);
    // consentRevoked は残る。
    const remaining = await readDashboardLog(storage);
    expect(remaining.map((e) => e.type)).toEqual(['consentRevoked']);
    // 削除監査記録は保全される（purge 対象外）。
    const records = await readLogPartition(storage, 'deletion-log/');
    expect(records.map((e) => e.type)).toEqual(['credentialDeleted']);
  });

  it('アクティブペルソナ未設定でも purgeDashboardLog は動作する（署名不要）', async () => {
    const storage = new MemoryStorage();
    const withPersona = await createWallet({ storage });
    await withPersona.importMnemonic(TEST_MNEMONIC);
    const persona = await withPersona.createPersona();
    await withPersona.setActivePersona(persona.id);
    await withPersona.storeCredential(makeVc('vc-1'));
    await withPersona.markCredentialDisputed('vc-1', '氏名誤り');

    // 同じ storage をペルソナ未設定の別 Wallet で開き直しても purge できる。
    const noPersona = await createWallet({ storage });
    await noPersona.importMnemonic(TEST_MNEMONIC);
    const deleted = await noPersona.purgeDashboardLog();

    expect(deleted).toBe(1);
    expect(await readDashboardLog(storage)).toHaveLength(0);
  });
});
