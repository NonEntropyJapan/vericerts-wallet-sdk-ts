/**
 * `PersonaManager` の `Object.prototype` 汚染耐性テスト。
 *
 * `opts?.index` をプロトタイプ鎖で読むと、index を**渡していない**正当な作成でも汚染値が
 * 採用され、全ペルソナが同一 HD 派生パスに固定される。ペルソナの非連結性（unlinkability）が
 * 壊れ、同じ鍵が使い回される。
 */

import { describe, expect, it } from 'bun:test';
import { MemoryStorage } from '../../../../storage/storage.js';
import { withPollutedPrototypeAsync } from '../../../__tests__/prototype-pollution.fixtures.js';
import { createDidKey } from '../../../identity/method-key.js';
import { p256DidPath } from '../../../keymanager/derivation/slip10.js';
import { KeyManager } from '../../../keymanager/keymanager.js';
import { PersonaManager } from '../../persona.js';
import type { CreatePersonaOptions } from '../../types.js';

const TEST_MNEMONIC =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

function fixedClock(start = 1_000): () => number {
  let value = start;
  return () => value++;
}

async function newManager(): Promise<PersonaManager> {
  const km = new KeyManager();
  await km.importMnemonic(TEST_MNEMONIC);
  return new PersonaManager(km, new MemoryStorage(), createDidKey, fixedClock());
}

describe('PersonaManager の Object.prototype 汚染耐性', () => {
  it('オプションオブジェクトが継承した index は採用しない', async () => {
    const manager = await newManager();
    // `index` を**オプションオブジェクト自身のプロトタイプ**へ仕込む経路。
    // `Object.prototype` を汚染する経路は 修正後に検証できるようになったため、
    // 直後の end-to-end テストで別途カバーしている。
    const inherited = Object.create({ index: 42 }) as CreatePersonaOptions;
    expect(inherited.index).toBe(42);
    expect(Object.hasOwn(inherited, 'index')).toBe(false);

    const first = await manager.createPersona(inherited);
    const second = await manager.createPersona(inherited);
    expect(first.index).toBe(0);
    expect(second.index).toBe(1);
    expect(first.derivationPath).toBe(p256DidPath(0));
    expect(second.derivationPath).toBe(p256DidPath(1));
    expect(first.did).not.toBe(second.did);
  });

  it('Object.prototype.index 汚染下でもペルソナ作成が成功し継承値を採用しない', async () => {
    const manager = await newManager();
    // 修正前は `@scure/bip32` の `HDKey` 生成がプロトタイプ鎖から `index` を拾って
    // 失敗するため、この end-to-end 検証自体が書けなかった。
    const [first, second] = await withPollutedPrototypeAsync({ index: 42 }, async () => [
      await manager.createPersona({}),
      await manager.createPersona({}),
    ]);

    expect(first?.index).toBe(0);
    expect(second?.index).toBe(1);
    expect(first?.derivationPath).toBe(p256DidPath(0));
    expect(second?.derivationPath).toBe(p256DidPath(1));
    expect(first?.did).not.toBe(second?.did);
  });

  it('継承した label はメタデータに載らない', async () => {
    const manager = await newManager();
    // **オプションオブジェクトを渡す**こと。引数なし呼び出しだと `opts?.label` が
    // オプショナルチェーンで短絡し、修正前でも `undefined` になってトートロジーになる。
    const persona = await withPollutedPrototypeAsync({ label: 'attacker-label' }, () =>
      manager.createPersona({}),
    );
    expect(persona.label).toBeUndefined();
  });

  it('オプションオブジェクトが継承した label もメタデータに載らない', async () => {
    const manager = await newManager();
    const inherited = Object.create({ label: 'attacker-label' }) as CreatePersonaOptions;
    const persona = await manager.createPersona(inherited);
    expect(persona.label).toBeUndefined();
  });

  it('継承した label は一覧のフィルタ条件にならない', async () => {
    const manager = await newManager();
    await manager.createPersona({ label: 'mine' });
    await manager.createPersona();
    // 同上。空のオプションオブジェクトを渡してプロトタイプ鎖の読み取りを発生させる。
    const listed = await withPollutedPrototypeAsync({ label: 'mine' }, () =>
      manager.listPersonas({}),
    );
    // フィルタ条件を渡していないので 2 件とも返るのが正。
    expect(listed).toHaveLength(2);
  });

  it('明示的に渡した index / label は従来どおり反映される（正常系）', async () => {
    const manager = await newManager();
    const persona = await manager.createPersona({ index: 5, label: 'work' });
    expect(persona.index).toBe(5);
    expect(persona.label).toBe('work');
    expect(persona.derivationPath).toBe(p256DidPath(5));
  });
});
