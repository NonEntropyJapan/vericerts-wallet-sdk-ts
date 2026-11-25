/**
 * `createPersona` の `label` 型検査。
 *
 * 読み取り側（`decodeMetadata`）は非文字列の label を 2005 で拒否するため、書き込み側で通すと
 * 以後 `listPersonas` / `createPersona` が恒久的に 2005 になる。永続化前に 1040 で拒否する。
 */

import { describe, expect, it } from 'bun:test';
import { MemoryStorage } from '../../../storage/storage.js';
import { VericertsError } from '../../errors.js';
import { createDidKey } from '../../identity/method-key.js';
import { KeyManager } from '../../keymanager/keymanager.js';
import { PersonaManager } from '../persona.js';

const TEST_MNEMONIC =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

describe('PersonaManager.createPersona の label 検査', () => {
  it.each([
    ['数値', 5],
    ['null', null],
    ['オブジェクト', {}],
    ['配列', ['a']],
  ])('label が%sなら 1040 で拒否し、何も永続化せず以後の操作も壊れない', async (_name, bad) => {
    const km = new KeyManager();
    await km.importMnemonic(TEST_MNEMONIC);
    const storage = new MemoryStorage();
    const manager = new PersonaManager(km, storage, createDidKey);

    const error = await manager.createPersona({ label: bad as unknown as string }).then(
      () => null,
      (e: unknown) => e,
    );
    expect(error).toBeInstanceOf(VericertsError);
    expect((error as VericertsError).code).toBe('1040');

    expect(await storage.list('persona/')).toEqual([]);
    expect(await manager.listPersonas()).toEqual([]);
    expect((await manager.createPersona({ label: 'ok' })).label).toBe('ok');
  });

  it('label 省略・undefined・空文字は従来どおり受理する', async () => {
    const km = new KeyManager();
    await km.importMnemonic(TEST_MNEMONIC);
    const manager = new PersonaManager(km, new MemoryStorage(), createDidKey);
    await manager.createPersona();
    await manager.createPersona({ label: undefined });
    const empty = await manager.createPersona({ label: '' });
    expect(empty.label).toBe('');
    expect(await manager.listPersonas()).toHaveLength(3);
  });
});
