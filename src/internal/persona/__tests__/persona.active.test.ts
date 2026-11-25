/**
 * PersonaManager のアクティブペルソナ管理の振る舞い検証。
 *
 * setActivePersona / getActivePersona の永続化・lastUsedAt 更新・未存在エラーを検証する。
 */

import { describe, expect, it } from 'bun:test';
import { MemoryStorage } from '../../../storage/storage.js';
import { VericertsError } from '../../errors.js';
import { createDidKey } from '../../identity/method-key.js';
import { KeyManager } from '../../keymanager/keymanager.js';
import { PersonaManager } from '../persona.js';
import type { PersonaMetadata } from '../types.js';

const TEST_MNEMONIC =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

function fixedClock(start = 1_000): () => number {
  let value = start;
  return () => value++;
}

async function newManager(now: () => number): Promise<PersonaManager> {
  const km = new KeyManager();
  await km.importMnemonic(TEST_MNEMONIC);
  return new PersonaManager(km, new MemoryStorage(), createDidKey, now);
}

describe('PersonaManager アクティブペルソナ管理', () => {
  it('未設定時 getActivePersona は null', async () => {
    const manager = await newManager(fixedClock());
    expect(await manager.getActivePersona()).toBeNull();
  });

  it('setActivePersona 後に getActivePersona が同一 id を返す', async () => {
    const manager = await newManager(fixedClock());
    const persona = await manager.createPersona();
    await manager.setActivePersona(persona.id);
    const active = await manager.getActivePersona();
    expect(active?.id).toBe(persona.id);
  });

  it('setActivePersona は lastUsedAt を現在時刻へ更新する', async () => {
    const clock = fixedClock(100);
    const manager = await newManager(clock);
    const persona = await manager.createPersona();
    const updated = await manager.setActivePersona(persona.id);
    expect(updated.lastUsedAt).toBeGreaterThan(persona.lastUsedAt);
    // createdAt は不変。
    expect(updated.createdAt).toBe(persona.createdAt);
    const reloaded = await manager.getActivePersona();
    expect(reloaded?.lastUsedAt).toBe(updated.lastUsedAt);
  });

  it('複数ペルソナ間で切替できる', async () => {
    const manager = await newManager(fixedClock());
    const first = await manager.createPersona();
    const second = await manager.createPersona();
    await manager.setActivePersona(first.id);
    expect((await manager.getActivePersona())?.id).toBe(first.id);
    await manager.setActivePersona(second.id);
    expect((await manager.getActivePersona())?.id).toBe(second.id);
  });

  it('未存在 id を setActivePersona すると 2005 を投げる', async () => {
    const manager = await newManager(fixedClock());
    await expect(manager.setActivePersona('did:key:zUnknown')).rejects.toMatchObject({
      code: '2005',
    });
    await expect(manager.setActivePersona('did:key:zUnknown')).rejects.toBeInstanceOf(
      VericertsError,
    );
  });

  it('切替時に登録済みリスナへ更新後メタデータを通知する', async () => {
    const manager = await newManager(fixedClock());
    const persona = await manager.createPersona();
    const received: PersonaMetadata[] = [];
    manager.onPersonaSwitch((p) => received.push(p));
    const updated = await manager.setActivePersona(persona.id);
    expect(received).toHaveLength(1);
    expect(received[0]?.id).toBe(persona.id);
    expect(received[0]?.lastUsedAt).toBe(updated.lastUsedAt);
  });

  it('購読解除後はリスナへ通知しない', async () => {
    const manager = await newManager(fixedClock());
    const first = await manager.createPersona();
    const second = await manager.createPersona();
    let count = 0;
    const unsubscribe = manager.onPersonaSwitch(() => {
      count++;
    });
    await manager.setActivePersona(first.id);
    unsubscribe();
    await manager.setActivePersona(second.id);
    expect(count).toBe(1);
  });

  it('アクティブ参照先が破損していると getActivePersona は 2005 を伝播する', async () => {
    const km = new KeyManager();
    await km.importMnemonic(TEST_MNEMONIC);
    const storage = new MemoryStorage();
    const manager = new PersonaManager(km, storage, createDidKey, fixedClock());
    const persona = await manager.createPersona();
    await manager.setActivePersona(persona.id);
    // 参照先メタデータを破損させる（不正な JSON）。
    await storage.set(`persona/${persona.id}`, new TextEncoder().encode('{ broken'));
    await expect(manager.getActivePersona()).rejects.toMatchObject({ code: '2005' });
  });

  it('リスナの例外は切替処理の成否に影響しない', async () => {
    const manager = await newManager(fixedClock());
    const persona = await manager.createPersona();
    manager.onPersonaSwitch(() => {
      throw new Error('listener boom');
    });
    const updated = await manager.setActivePersona(persona.id);
    expect(updated.id).toBe(persona.id);
    expect((await manager.getActivePersona())?.id).toBe(persona.id);
  });
});
