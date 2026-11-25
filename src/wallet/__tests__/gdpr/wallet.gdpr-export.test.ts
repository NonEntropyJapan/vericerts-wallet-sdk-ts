/**
 * Wallet ファサードの GDPR exportDashboardLog（Art.15 アクセス権 / Art.20 データポータビリティ）統合テスト。
 *
 * createWallet 経由（実 storage / 実鍵）で以下を検証する:
 * - exportDashboardLog はユーザー制御 Dashboard ログを application/x-ndjson の Blob（各行 JWS 署名付き +
 *   末尾 Merkle ルートハッシュ行）でエクスポートし、読み出しのみで storage を変更しない。
 * - filter で export 対象を絞り込む。
 * - 削除監査記録（deletion-log/）は export 対象外。
 * - 署名不要のためアクティブペルソナ未設定でも動作する。
 * - 空ログの export は Merkle ルートハッシュ行のみ（merkleRoot: null）。
 */

import { describe, expect, it } from 'bun:test';
import type { VerifiableCredential } from '../../../internal/credential/index.js';
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

/** storage からユーザー制御 Dashboard ログのキー数を数える。 */
async function countDashboardLog(storage: MemoryStorage): Promise<number> {
  return (await storage.list('dashboard-log/')).length;
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

/** Blob のテキストを行配列にパースする（末尾の Merkle ルートハッシュ行を含む）。 */
async function parseExport(blob: Blob): Promise<Record<string, unknown>[]> {
  const text = await blob.text();
  return text.split('\n').map((line) => JSON.parse(line) as Record<string, unknown>);
}

describe('Wallet GDPR exportDashboardLog', () => {
  it('application/x-ndjson の Blob を返し、ユーザー制御ログ各行 + Merkle ルートハッシュ行を含む', async () => {
    const { wallet, storage } = await setup();
    await wallet.storeCredential(makeVc('vc-1'));
    await wallet.markCredentialDisputed('vc-1', '氏名誤り');
    await wallet.revokeConsent({ rpIdentifier: 'did:web:rp.example' });

    const blob = await wallet.exportDashboardLog();

    expect(blob.type).toBe('application/x-ndjson');
    const lines = await parseExport(blob);
    // correctionRequest + consentRevoked の 2 エントリ + Merkle ルートハッシュ行。
    expect(lines).toHaveLength(3);
    expect(lines.slice(0, 2).map((l) => l.type)).toEqual(['correctionRequest', 'consentRevoked']);
    expect(lines[2]?.count).toBe(2);
    expect(typeof lines[2]?.merkleRoot).toBe('string');
    // エクスポートは読み出しのみ: ストレージのログは変更されない。
    expect(await countDashboardLog(storage)).toBe(2);
  });

  it('filter で export 対象を絞り込む', async () => {
    const { wallet } = await setup();
    await wallet.storeCredential(makeVc('vc-1'));
    await wallet.markCredentialDisputed('vc-1', '氏名誤り');
    await wallet.revokeConsent({ rpIdentifier: 'did:web:rp.example' });

    const blob = await wallet.exportDashboardLog({ types: ['correctionRequest'] });
    const lines = await parseExport(blob);

    // correctionRequest 1 件 + ルートハッシュ行。
    expect(lines).toHaveLength(2);
    expect(lines[0]?.type).toBe('correctionRequest');
    expect(lines[1]?.count).toBe(1);
  });

  it('削除監査記録（deletion-log/）は export 対象外', async () => {
    const { wallet } = await setup();
    await wallet.storeCredential(makeVc('vc-1'));
    await wallet.markCredentialDisputed('vc-1', '氏名誤り');
    await wallet.storeCredential(makeVc('vc-2'));
    await wallet.deleteCredential('vc-2');

    const lines = await parseExport(await wallet.exportDashboardLog());

    // ユーザー制御ログ 1 件（correctionRequest）+ ルートハッシュ行のみ（credentialDeleted は含まない）。
    expect(lines).toHaveLength(2);
    expect(lines[0]?.type).toBe('correctionRequest');
    expect(lines[1]?.count).toBe(1);
  });

  it('アクティブペルソナ未設定でも exportDashboardLog は動作する（署名不要）', async () => {
    const storage = new MemoryStorage();
    const withPersona = await createWallet({ storage });
    await withPersona.importMnemonic(TEST_MNEMONIC);
    const persona = await withPersona.createPersona();
    await withPersona.setActivePersona(persona.id);
    await withPersona.storeCredential(makeVc('vc-1'));
    await withPersona.markCredentialDisputed('vc-1', '氏名誤り');

    // 同じ storage をペルソナ未設定の別 Wallet で開き直しても export できる。
    const noPersona = await createWallet({ storage });
    await noPersona.importMnemonic(TEST_MNEMONIC);
    const lines = await parseExport(await noPersona.exportDashboardLog());

    expect(lines).toHaveLength(2);
    expect(lines[0]?.type).toBe('correctionRequest');
    expect(lines[1]?.count).toBe(1);
  });

  it('空ログの export は Merkle ルートハッシュ行のみ（merkleRoot: null）', async () => {
    const { wallet } = await setup();

    const lines = await parseExport(await wallet.exportDashboardLog());

    expect(lines).toEqual([{ merkleRoot: null, count: 0 }]);
  });
});
