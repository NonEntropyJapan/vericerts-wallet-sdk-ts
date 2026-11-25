/**
 * `WalletRecordStore`（ウォレットルートエンティティの永続化層）の振る舞い検証。
 *
 * 初回作成の採番・永続化、2 回目以降の冪等性（id / createdAt を再生成しない）、
 * `activePersonaDID` / `personas` が複製ではなく `PersonaManager` 由来のライブ値であること、
 * `touch` の更新範囲、storage 破損時の 6005 正規化を検証する。
 */

import { describe, expect, it } from 'bun:test';
import { VericertsError } from '../../internal/errors.js';
import { createDidKey } from '../../internal/identity/method-key.js';
import { KeyManager } from '../../internal/keymanager/keymanager.js';
import { PersonaManager } from '../../internal/persona/persona.js';
import { MemoryStorage } from '../../storage/storage.js';
import { WalletRecordStore } from '../wallet-record.js';

// BIP-39 公式オールゼロ・エントロピーのニーモニック（passphrase なし）。
const TEST_MNEMONIC =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

/** 呼び出しごとに 1 ずつ進む決定的な時計。 */
function fixedClock(start = 1_000): () => number {
  let value = start;
  return () => value++;
}

/** 連番の決定的な id 採番関数。 */
function fixedIdGen(): () => string {
  let count = 0;
  return () => `wallet-${count++}`;
}

/** storage を共有する PersonaManager + WalletRecordStore 一式を用意する。 */
async function setup(now: () => number = fixedClock()): Promise<{
  storage: MemoryStorage;
  personas: PersonaManager;
  store: WalletRecordStore;
}> {
  const keymanager = new KeyManager();
  await keymanager.importMnemonic(TEST_MNEMONIC);
  const storage = new MemoryStorage();
  const personas = new PersonaManager(keymanager, storage, createDidKey, now);
  const store = new WalletRecordStore(storage, personas, now, fixedIdGen());
  return { storage, personas, store };
}

describe('WalletRecordStore', () => {
  it('初回 get でルートメタデータを採番・永続化する', async () => {
    const { storage, store } = await setup();
    const record = await store.get();
    expect(record.id).toBe('wallet-0');
    expect(record.version).toBe('1');
    expect(record.createdAt).toBe(record.updatedAt);
    // storage へ実際に永続化されている（インメモリ保持だけではない）。
    expect(await storage.get('wallet/metadata')).not.toBeNull();
  });

  it('2 回目の get は同一 id / createdAt を返す（再採番しない）', async () => {
    const { store } = await setup();
    const first = await store.get();
    const second = await store.get();
    expect(second.id).toBe(first.id);
    expect(second.createdAt).toBe(first.createdAt);
    expect(second.updatedAt).toBe(first.updatedAt);
  });

  it('別インスタンスからも永続化済みの id / createdAt を読み出す', async () => {
    const { storage, personas, store } = await setup();
    const first = await store.get();
    const reloaded = new WalletRecordStore(storage, personas, fixedClock(9_000), fixedIdGen());
    const second = await reloaded.get();
    expect(second.id).toBe(first.id);
    expect(second.createdAt).toBe(first.createdAt);
  });

  it('アクティブペルソナ未設定なら activePersonaDID は null・personas は空', async () => {
    const { store } = await setup();
    const record = await store.get();
    expect(record.activePersonaDID).toBeNull();
    expect(record.personas).toEqual([]);
  });

  it('ペルソナ作成・切替をライブに反映する（スナップショットを複製しない）', async () => {
    const { personas, store } = await setup();
    // 先に get してルートメタデータを永続化しておく（以降の変更が複製されないことを見る）。
    await store.get();
    const persona = await personas.createPersona({ label: '仕事' });
    await personas.setActivePersona(persona.id);
    const record = await store.get();
    expect(record.activePersonaDID).toBe(persona.did);
    expect(record.personas).toHaveLength(1);
    expect(record.personas[0]?.id).toBe(persona.id);
  });

  it('touch は updatedAt のみ更新し id / version / createdAt は不変', async () => {
    const { store } = await setup();
    const before = await store.get();
    await store.touch();
    const after = await store.get();
    expect(after.updatedAt).toBeGreaterThan(before.updatedAt);
    expect(after.id).toBe(before.id);
    expect(after.version).toBe(before.version);
    expect(after.createdAt).toBe(before.createdAt);
  });

  it('未作成状態で touch しても初回作成したうえで更新する', async () => {
    const { store } = await setup();
    await store.touch();
    const record = await store.get();
    expect(record.id).toBe('wallet-0');
    expect(record.updatedAt).toBeGreaterThan(record.createdAt);
  });

  it('初回の並行 get が同一 id を返し、永続化されるのも同じ id', async () => {
    const { store, storage } = await setup();
    const [a, b, c] = await Promise.all([store.get(), store.get(), store.get()]);
    expect(b.id).toBe(a.id);
    expect(c.id).toBe(a.id);
    expect((await new WalletRecordStore(storage, (await setup()).personas).get()).id).toBe(a.id);
  });

  it('wallet/metadata が破損していると get は 6005 を投げる', async () => {
    const { storage, store } = await setup();
    await storage.set('wallet/metadata', new TextEncoder().encode('{ broken'));
    await expect(store.get()).rejects.toMatchObject({ code: '6005' });
    await expect(store.get()).rejects.toBeInstanceOf(VericertsError);
  });

  it('wallet/metadata の必須フィールド欠落も 6005 として扱う', async () => {
    const { storage, store } = await setup();
    await storage.set('wallet/metadata', new TextEncoder().encode('{"id":"w","version":"1"}'));
    await expect(store.get()).rejects.toMatchObject({ code: '6005' });
    await expect(store.touch()).rejects.toMatchObject({ code: '6005' });
  });
});
