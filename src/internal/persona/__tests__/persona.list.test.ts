/**
 * PersonaManager.listPersonasの振る舞い検証。
 *
 * フィルタ・ソート（createdAt / lastUsedAt / label）と破損データの正規化を検証する。
 */

import { describe, expect, it } from 'bun:test';
import { MemoryStorage } from '../../../storage/storage.js';
import { createDidKey } from '../../identity/method-key.js';
import { KeyManager } from '../../keymanager/keymanager.js';
import { PersonaManager } from '../persona.js';

const TEST_MNEMONIC =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

function fixedClock(start = 1_000): () => number {
  let value = start;
  return () => value++;
}

async function setup(): Promise<{ manager: PersonaManager; storage: MemoryStorage }> {
  const km = new KeyManager();
  await km.importMnemonic(TEST_MNEMONIC);
  const storage = new MemoryStorage();
  const manager = new PersonaManager(km, storage, createDidKey, fixedClock());
  return { manager, storage };
}

describe('PersonaManager.listPersonas', () => {
  it('ゼロ件なら空配列', async () => {
    const { manager } = await setup();
    expect(await manager.listPersonas()).toEqual([]);
  });

  it('作成した全ペルソナを返し、active キーは混入しない', async () => {
    const { manager } = await setup();
    const a = await manager.createPersona({ label: 'A' });
    const b = await manager.createPersona({ label: 'B' });
    await manager.setActivePersona(a.id);
    const list = await manager.listPersonas();
    expect(list.length).toBe(2);
    expect(list.map((p) => p.id).sort()).toEqual([a.id, b.id].sort());
  });

  it('label でフィルタできる', async () => {
    const { manager } = await setup();
    await manager.createPersona({ label: '仕事' });
    await manager.createPersona({ label: 'プライベート' });
    await manager.createPersona({ label: '仕事' });
    const filtered = await manager.listPersonas({ label: '仕事' });
    expect(filtered.length).toBe(2);
    expect(filtered.every((p) => p.label === '仕事')).toBe(true);
  });

  it('既定は createdAt 昇順', async () => {
    const { manager } = await setup();
    const a = await manager.createPersona();
    const b = await manager.createPersona();
    const list = await manager.listPersonas();
    expect(list.map((p) => p.createdAt)).toEqual([a.createdAt, b.createdAt]);
    expect(list[0]?.createdAt).toBeLessThan(list[1]?.createdAt ?? 0);
  });

  it('createdAt 降順ソート', async () => {
    const { manager } = await setup();
    await manager.createPersona();
    await manager.createPersona();
    const list = await manager.listPersonas({ sortBy: 'createdAt', order: 'desc' });
    expect((list[0]?.createdAt ?? 0) > (list[1]?.createdAt ?? 0)).toBe(true);
  });

  it('lastUsedAt でソートできる', async () => {
    const { manager } = await setup();
    const a = await manager.createPersona();
    const b = await manager.createPersona();
    // a を後からアクティブにして lastUsedAt を最新化する。
    await manager.setActivePersona(a.id);
    const list = await manager.listPersonas({ sortBy: 'lastUsedAt', order: 'desc' });
    expect(list[0]?.id).toBe(a.id);
    expect(list[1]?.id).toBe(b.id);
  });

  it('label でソートできる', async () => {
    const { manager } = await setup();
    await manager.createPersona({ label: 'Charlie' });
    await manager.createPersona({ label: 'Alice' });
    await manager.createPersona({ label: 'Bob' });
    const list = await manager.listPersonas({ sortBy: 'label' });
    expect(list.map((p) => p.label)).toEqual(['Alice', 'Bob', 'Charlie']);
  });

  it('storage 上のデータ破損は 2005 に正規化される', async () => {
    const { manager, storage } = await setup();
    await storage.set('persona/did:key:zBroken', new TextEncoder().encode('{not json'));
    await expect(manager.listPersonas()).rejects.toMatchObject({ code: '2005' });
  });
});
