/**
 * Wallet ファサードの persona 配線（統合）テスト。
 *
 * createWallet が PersonaManager を keymanager / storage / createDidKey と共有して配線し、
 * createPersona → listPersonas → setActivePersona → getActivePersona の一連が
 * ファサード経由で動作することを検証する。
 */

import { describe, expect, it } from 'bun:test';
import { VericertsError } from '../../internal/errors.js';
import { MemoryStorage } from '../../storage/storage.js';
import { createWallet } from '../factory.js';
import { findLog, recordingLogger } from './metrics/logger.fixtures.js';

const TEST_MNEMONIC =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

/** importMnemonic 済みの Wallet を返す。 */
async function setupInitialized() {
  const wallet = await createWallet({ storage: new MemoryStorage() });
  await wallet.importMnemonic(TEST_MNEMONIC);
  return wallet;
}

describe('Wallet persona 配線', () => {
  it('createPersona は did:key の ID を持つメタデータを返し、listPersonas に現れる', async () => {
    const wallet = await setupInitialized();
    const p = await wallet.createPersona({ label: 'main' });
    expect(p.did.startsWith('did:key:z')).toBe(true);
    expect(p.id).toBe(p.did);
    expect(p.label).toBe('main');
    const list = await wallet.listPersonas();
    expect(list.map((x) => x.id)).toContain(p.did);
  });

  it('setActivePersona / getActivePersona がファサード経由で機能する', async () => {
    const wallet = await setupInitialized();
    const p0 = await wallet.createPersona();
    const p1 = await wallet.createPersona();
    expect(await wallet.getActivePersona()).toBeNull();
    const active = await wallet.setActivePersona(p1.id);
    expect(active.id).toBe(p1.id);
    expect((await wallet.getActivePersona())?.id).toBe(p1.id);
    // 別ペルソナへ切り替えられる。
    await wallet.setActivePersona(p0.id);
    expect((await wallet.getActivePersona())?.id).toBe(p0.id);
  });

  it('masterSeed 未設定で createPersona は 1041 を投げる', async () => {
    const wallet = await createWallet({ storage: new MemoryStorage() });
    try {
      await wallet.createPersona();
      throw new Error('should have thrown');
    } catch (error) {
      expect(error).toBeInstanceOf(VericertsError);
      expect((error as VericertsError).code).toBe('1041');
    }
  });

  it('未存在ペルソナへの setActivePersona は 2005 を投げる', async () => {
    const wallet = await setupInitialized();
    try {
      await wallet.setActivePersona('did:key:zNonExistent');
      throw new Error('should have thrown');
    } catch (error) {
      expect(error).toBeInstanceOf(VericertsError);
      expect((error as VericertsError).code).toBe('2005');
    }
  });

  it('ペルソナ切替でウォレットルートメタデータが永続化される', async () => {
    const storage = new MemoryStorage();
    const wallet = await createWallet({ storage });
    await wallet.importMnemonic(TEST_MNEMONIC);
    const persona = await wallet.createPersona();
    // 切替前は誰も WalletRecordStore を読んでいないため、ルートメタデータは未作成。
    expect(await storage.get('wallet/metadata')).toBeNull();
    await wallet.setActivePersona(persona.id);
    // touch は fire-and-forget（`void`）で起動されるため、保留中のタスクを flush してから観測する。
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(await storage.get('wallet/metadata')).not.toBeNull();
  });

  it('wallet/metadata 破損時も setActivePersona は成功し、touch 失敗は unhandled rejection にならず warn で記録される', async () => {
    const storage = new MemoryStorage();
    const { logger, logs } = recordingLogger();
    const wallet = await createWallet({ storage, logger });
    await wallet.importMnemonic(TEST_MNEMONIC);
    const persona = await wallet.createPersona();
    await storage.set('wallet/metadata', new TextEncoder().encode('{corrupt'));

    const unhandled: unknown[] = [];
    const onUnhandled = (reason: unknown): void => {
      unhandled.push(reason);
    };
    process.on('unhandledRejection', onUnhandled);
    try {
      await wallet.setActivePersona(persona.id);
      await new Promise((resolve) => setTimeout(resolve, 20));
    } finally {
      process.off('unhandledRejection', onUnhandled);
    }

    expect(unhandled).toEqual([]);
    expect(findLog(logs, 'warn', 'wallet.record.touch')?.attrs).toMatchObject({
      component: 'sdk.wallet',
    });
  });
});
