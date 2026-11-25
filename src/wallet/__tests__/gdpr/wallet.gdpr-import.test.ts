/**
 * Wallet ファサードの GDPR importDashboardLog（Art.20 データポータビリティ）
 * 統合テスト。
 *
 * createWallet 経由（実 storage / 実鍵）で以下を検証する:
 * - export → import ラウンドトリップ: 別 Wallet（別 storage）へ Blob をインポートし、署名・Merkle chain を
 *   検証したうえで復元する（再 export が元と一致）。
 * - NDJSON 文字列でもインポートできる（Blob / string 両対応）。
 * - 検証鍵が署名者と異なると署名検証に失敗して拒否する（3010）。改ざん NDJSON も拒否する（3010）。
 * - 既存 Dashboard ログが空でない Wallet へのインポートは 10604 で拒否する。
 * - インポートしたエントリはユーザー制御ログとして list / export で読み出せる。
 */

import { describe, expect, it } from 'bun:test';
import type { VerifiableCredential } from '../../../internal/credential/index.js';
import { didDocumentToVerifierKey } from '../../../internal/credential/index.js';
import type { DashboardLogVerifierKey } from '../../../internal/gdpr/index.js';
import { MemoryStorage } from '../../../storage/storage.js';
import { createWallet } from '../../factory.js';
import type { Wallet } from '../../types.js';

const TEST_MNEMONIC =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const VC_V2_CONTEXT = 'https://www.w3.org/ns/credentials/v2';

/** import 済み + アクティブペルソナ設定済みの Wallet を用意する。 */
async function setup(): Promise<{ wallet: Wallet; personaDid: string }> {
  const wallet = await createWallet({ storage: new MemoryStorage() });
  await wallet.importMnemonic(TEST_MNEMONIC);
  const persona = await wallet.createPersona();
  await wallet.setActivePersona(persona.id);
  return { wallet, personaDid: persona.did };
}

/** ペルソナ DID（did:key P-256）を解決して import 検証鍵を組み立てる。 */
async function verifierKeyOf(wallet: Wallet, did: string): Promise<DashboardLogVerifierKey> {
  const key = didDocumentToVerifierKey(await wallet.resolveDID(did));
  if (key.publicKeyJwk === undefined) {
    throw new Error('persona DID から公開鍵 JWK を取得できない');
  }
  // 新規作成のペルソナ鍵は did:key P-256 のため署名 alg は ES256。
  return { alg: 'ES256', publicKeyJwk: key.publicKeyJwk };
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

/** ユーザー制御 Dashboard ログエントリを 2 件持つ Wallet を用意し、export Blob と検証鍵を返す。 */
async function exportedSource(): Promise<{ blob: Blob; verifierKey: DashboardLogVerifierKey }> {
  const { wallet, personaDid } = await setup();
  await wallet.storeCredential(makeVc('vc-1'));
  await wallet.markCredentialDisputed('vc-1', '氏名誤り');
  await wallet.revokeConsent({ rpIdentifier: 'did:web:rp.example' });
  return {
    blob: await wallet.exportDashboardLog(),
    verifierKey: await verifierKeyOf(wallet, personaDid),
  };
}

describe('Wallet GDPR importDashboardLog', () => {
  it('export → import ラウンドトリップ: 別 Wallet に復元し再 export が一致する', async () => {
    const { blob, verifierKey } = await exportedSource();
    const original = await blob.text();

    // 別 storage の Wallet へインポートする（新規 / 復旧端末を想定）。
    const { wallet: dest } = await setup();
    const imported = await dest.importDashboardLog(blob, verifierKey);

    expect(imported).toBe(2);
    // 復元したユーザー制御ログを再 export すると元の NDJSON と一致する（署名・prevHash を保持）。
    const reexported = await (await dest.exportDashboardLog()).text();
    expect(reexported).toBe(original);
  });

  it('NDJSON 文字列でもインポートできる（Blob / string 両対応）', async () => {
    const { blob, verifierKey } = await exportedSource();
    const { wallet: dest } = await setup();

    const imported = await dest.importDashboardLog(await blob.text(), verifierKey);

    expect(imported).toBe(2);
  });

  it('検証鍵が署名者と異なると署名検証に失敗して拒否する（3010）', async () => {
    const { blob } = await exportedSource();
    // 別ペルソナ（別導出パス = 別鍵）の検証鍵を使う（署名者と不一致）。
    const { wallet: dest } = await setup();
    const otherPersona = await dest.createPersona();
    const wrongKey = await verifierKeyOf(dest, otherPersona.did);

    await expect(dest.importDashboardLog(blob, wrongKey)).rejects.toMatchObject({ code: '3010' });
    // 拒否時はインポート先ログを変更しない。
    const lines = (await (await dest.exportDashboardLog()).text()).split('\n');
    expect(lines).toEqual(['{"merkleRoot":null,"count":0}']);
  });

  it('改ざんされた NDJSON は署名検証に失敗して拒否する（3010）', async () => {
    const { blob, verifierKey } = await exportedSource();
    const lines = (await blob.text()).split('\n');
    const tampered = JSON.parse(lines[0] as string) as { payload: { reason: string } };
    tampered.payload.reason = 'tampered';
    lines[0] = JSON.stringify(tampered);
    const { wallet: dest } = await setup();

    await expect(dest.importDashboardLog(lines.join('\n'), verifierKey)).rejects.toMatchObject({
      code: '3010',
    });
  });

  it('既存 Dashboard ログが空でない Wallet へのインポートは 10604 で拒否する', async () => {
    const { blob, verifierKey } = await exportedSource();
    // 既存エントリを 1 件持つインポート先。
    const { wallet: dest } = await setup();
    await dest.storeCredential(makeVc('existing'));
    await dest.markCredentialDisputed('existing', '既存');

    await expect(dest.importDashboardLog(blob, verifierKey)).rejects.toMatchObject({
      code: '10604',
    });
  });

  it('インポートしたエントリはユーザー制御ログとして export で読み出せる', async () => {
    const { blob, verifierKey } = await exportedSource();
    const { wallet: dest } = await setup();

    await dest.importDashboardLog(blob, verifierKey);

    const lines = (await (await dest.exportDashboardLog()).text())
      .split('\n')
      .map((line) => JSON.parse(line) as Record<string, unknown>);
    expect(lines.slice(0, 2).map((l) => l.type)).toEqual(['correctionRequest', 'consentRevoked']);
    expect(lines[2]?.count).toBe(2);
  });
});
