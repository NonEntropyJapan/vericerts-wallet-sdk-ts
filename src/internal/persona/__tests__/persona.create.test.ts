/**
 * PersonaManager.createPersona（サブ DID 派生）の振る舞い検証。
 *
 * 固定ニーモニックと注入時刻関数で決定性を確保し、ペルソナ index → 導出パス → did:key 生成 →
 * メタデータ永続化までを MemoryStorage + 実 KeyManager で結合的に検証する。
 */

import { describe, expect, it } from 'bun:test';
import { MemoryStorage } from '../../../storage/storage.js';
import { VericertsError } from '../../errors.js';
import { createDidKey } from '../../identity/method-key.js';
import { p256DidPath } from '../../keymanager/derivation/slip10.js';
import { KeyManager } from '../../keymanager/keymanager.js';
import { PersonaManager } from '../persona.js';

const TEST_MNEMONIC =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

function fixedClock(start = 1_000): () => number {
  let value = start;
  return () => value++;
}

async function newManager(now: () => number = fixedClock()): Promise<PersonaManager> {
  const km = new KeyManager();
  await km.importMnemonic(TEST_MNEMONIC);
  return new PersonaManager(km, new MemoryStorage(), createDidKey, now);
}

describe('PersonaManager.createPersona', () => {
  it('既定では index 0 のペルソナを did:key（P-256）で作成する（EOA アドレスは持たない）', async () => {
    const manager = await newManager();
    const persona = await manager.createPersona();
    expect(persona.index).toBe(0);
    expect(persona.derivationPath).toBe(p256DidPath(0));
    expect(persona.did.startsWith('did:key:zDn')).toBe(true);
    expect(persona.id).toBe(persona.did);
    expect(persona.address).toBeUndefined();
    expect(persona.createdAt).toBe(persona.lastUsedAt);
  });

  it('label を指定すると metadata に保持される', async () => {
    const manager = await newManager();
    const persona = await manager.createPersona({ label: '仕事' });
    expect(persona.label).toBe('仕事');
    const stored = await manager.getPersona(persona.id);
    expect(stored?.label).toBe('仕事');
  });

  it('index 省略時は既存最大 index + 1 を採番する', async () => {
    const manager = await newManager();
    const first = await manager.createPersona();
    const second = await manager.createPersona();
    const third = await manager.createPersona();
    expect(first.index).toBe(0);
    expect(second.index).toBe(1);
    expect(third.index).toBe(2);
    expect(second.did).not.toBe(first.did);
  });

  it('明示 index を指定でき、導出パスへ反映される', async () => {
    const manager = await newManager();
    const persona = await manager.createPersona({ index: 5 });
    expect(persona.index).toBe(5);
    expect(persona.derivationPath).toBe(p256DidPath(5));
  });

  it('同一ニーモニック・同一 index は決定的に同じ did を生成する', async () => {
    const a = await (await newManager()).createPersona({ index: 3 });
    const b = await (await newManager()).createPersona({ index: 3 });
    expect(b.did).toBe(a.did);
  });

  it('マスターシード未設定だと 1041 を投げる', async () => {
    const km = new KeyManager();
    const manager = new PersonaManager(km, new MemoryStorage(), createDidKey);
    await expect(manager.createPersona()).rejects.toMatchObject({ code: '1041' });
    await expect(manager.createPersona()).rejects.toBeInstanceOf(VericertsError);
  });

  it('負の index は 1040（導出パス不正）を投げる', async () => {
    const manager = await newManager();
    await expect(manager.createPersona({ index: -1 })).rejects.toMatchObject({ code: '1040' });
  });

  it('同一 index の二重作成は 2008 を投げ、既存メタデータを上書きしない', async () => {
    const manager = await newManager();
    const first = await manager.createPersona({ index: 2, label: '最初' });
    await expect(manager.createPersona({ index: 2, label: '上書き' })).rejects.toMatchObject({
      code: '2008',
    });
    await expect(manager.createPersona({ index: 2 })).rejects.toBeInstanceOf(VericertsError);
    // 既存メタデータ（label / createdAt）が破壊されていないこと。
    const stored = await manager.getPersona(first.id);
    expect(stored?.label).toBe('最初');
    expect(stored?.createdAt).toBe(first.createdAt);
  });

  it('返り値のフィールドが PersonaMetadata と一致する', async () => {
    const manager = await newManager();
    const persona = await manager.createPersona({ label: '仕事' });
    expect(Object.keys(persona).sort()).toEqual(
      [
        'id',
        'index',
        'did',
        'derivationPath',
        'label',
        'createdAt',
        'lastUsedAt',
        'method',
        'keyType',
        'kid',
      ].sort(),
    );
    expect(typeof persona.createdAt).toBe('number');
    expect(typeof persona.lastUsedAt).toBe('number');
    // spec が乖離前に要求していた name/type/delegatedDIDs は本型に存在しない
    // （UI 表示用ビューは呼び出し側が PersonaMetadata + DelegatedDIDStore から合成する）。
    expect(persona).not.toHaveProperty('name');
    expect(persona).not.toHaveProperty('type');
    expect(persona).not.toHaveProperty('delegatedDIDs');
  });

  it('index 省略の並行作成は別 index に採番され、双方のメタデータが残る', async () => {
    const manager = await newManager();
    const [a, b] = await Promise.all([
      manager.createPersona({ label: 'a' }),
      manager.createPersona({ label: 'b' }),
    ]);
    expect([a.index, b.index].sort()).toEqual([0, 1]);
    const labels = (await manager.listPersonas()).map((p) => p.label).sort();
    expect(labels).toEqual(['a', 'b']);
  });

  it('同一 index の並行作成は片方が 2008 になり、先勝ちのメタデータが残る', async () => {
    const manager = await newManager();
    const results = await Promise.allSettled([
      manager.createPersona({ index: 3, label: 'a' }),
      manager.createPersona({ index: 3, label: 'b' }),
    ]);
    expect(results[0].status).toBe('fulfilled');
    expect(results[1]).toMatchObject({ status: 'rejected', reason: { code: '2008' } });
    expect((await manager.listPersonas()).map((p) => p.label)).toEqual(['a']);
  });
});
