/**
 * `MemoryStorage` の振る舞い検証。
 *
 * set→get 往復、未存在・上書き・delete の冪等性、list の前方一致と昇順ソート、
 * 両端の防御的コピー、空 value と未存在の区別、バイナリ値の保持を確認する。
 */

import { describe, expect, it } from 'bun:test';
import { MemoryStorage } from '../storage.js';

describe('MemoryStorage', () => {
  it('set した値を get で同一内容として取得できる', async () => {
    const storage = new MemoryStorage();
    const value = new Uint8Array([1, 2, 3]);
    await storage.set('k', value);
    const got = await storage.get('k');
    expect(got).not.toBeNull();
    expect(Array.from(got as Uint8Array)).toEqual([1, 2, 3]);
  });

  it('未存在キーの get は null を返す', async () => {
    const storage = new MemoryStorage();
    expect(await storage.get('missing')).toBeNull();
  });

  it('同一キーへの set は最新値で上書きする', async () => {
    const storage = new MemoryStorage();
    await storage.set('k', new Uint8Array([1]));
    await storage.set('k', new Uint8Array([2, 3]));
    const got = await storage.get('k');
    expect(Array.from(got as Uint8Array)).toEqual([2, 3]);
  });

  it('delete 後の get は null を返す', async () => {
    const storage = new MemoryStorage();
    await storage.set('k', new Uint8Array([1]));
    await storage.delete('k');
    expect(await storage.get('k')).toBeNull();
  });

  it('未存在キーの delete は例外を投げず resolve する（冪等）', async () => {
    const storage = new MemoryStorage();
    await expect(storage.delete('missing')).resolves.toBeUndefined();
  });

  it('list は prefix に前方一致するキーのみ返す', async () => {
    const storage = new MemoryStorage();
    await storage.set('user:1', new Uint8Array([1]));
    await storage.set('user:2', new Uint8Array([2]));
    await storage.set('key:1', new Uint8Array([3]));
    expect(await storage.list('user:')).toEqual(['user:1', 'user:2']);
  });

  it("list('') は全件のキーを返す", async () => {
    const storage = new MemoryStorage();
    await storage.set('a', new Uint8Array([1]));
    await storage.set('b', new Uint8Array([2]));
    expect(await storage.list('')).toEqual(['a', 'b']);
  });

  it('list は該当なしの場合に空配列を返す', async () => {
    const storage = new MemoryStorage();
    await storage.set('a', new Uint8Array([1]));
    expect(await storage.list('z')).toEqual([]);
  });

  it('list の結果は挿入順に関わらずキー昇順でソートされる', async () => {
    const storage = new MemoryStorage();
    await storage.set('c', new Uint8Array([1]));
    await storage.set('a', new Uint8Array([2]));
    await storage.set('b', new Uint8Array([3]));
    expect(await storage.list('')).toEqual(['a', 'b', 'c']);
  });

  it('get の戻り値を変更しても内部状態は不変（防御的コピー）', async () => {
    const storage = new MemoryStorage();
    await storage.set('k', new Uint8Array([1, 2, 3]));
    const got = (await storage.get('k')) as Uint8Array;
    got[0] = 99;
    const again = (await storage.get('k')) as Uint8Array;
    expect(Array.from(again)).toEqual([1, 2, 3]);
  });

  it('set 後に元配列を変更しても内部状態は不変（防御的コピー）', async () => {
    const storage = new MemoryStorage();
    const value = new Uint8Array([1, 2, 3]);
    await storage.set('k', value);
    value[0] = 99;
    const got = (await storage.get('k')) as Uint8Array;
    expect(Array.from(got)).toEqual([1, 2, 3]);
  });

  it('空の value を set→get でき、null と区別される', async () => {
    const storage = new MemoryStorage();
    await storage.set('empty', new Uint8Array(0));
    const got = await storage.get('empty');
    expect(got).not.toBeNull();
    expect((got as Uint8Array).length).toBe(0);
  });

  it('0x00 / 0xff を含むバイナリ値をそのまま保持する', async () => {
    const storage = new MemoryStorage();
    const value = new Uint8Array([0x00, 0x7f, 0x80, 0xff]);
    await storage.set('bin', value);
    const got = (await storage.get('bin')) as Uint8Array;
    expect(Array.from(got)).toEqual([0x00, 0x7f, 0x80, 0xff]);
  });
});
