/**
 * persona メタデータの null プロトタイプ耐性テスト。
 *
 * `decodeMetadata` は `parseJsonWithoutPrototype` を通るため、storage 上のオブジェクト値は
 * `Object.prototype` を継承せず `toString` / `valueOf` を持たない。`isPersonaMetadata` が任意項目
 * `label` を検証しないままだと、型不正な値が `sortPersonas` の
 * `(a.label ?? '').localeCompare(b.label ?? '')` の**引数**に届き、引数側の暗黙 `ToString` が
 * `TypeError: No default value` になる。`listPersonas({ sortBy: 'label' })` が破損レコードに対する
 * 文書化された失敗（2005）ではなく生の例外を漏らす。
 *
 * **素のオブジェクトリテラルでは再現しない**（`'[object Object]'` として黙って比較されるだけ）。
 * 必ず `encode` / `decode` の実経路（storage へのバイト列書き込み → `listPersonas`）を通すこと。
 */

import { describe, expect, it } from 'bun:test';
import { MemoryStorage } from '../../../../storage/storage.js';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import { createDidKey } from '../../../identity/method-key.js';
import { KeyManager } from '../../../keymanager/keymanager.js';
import { PersonaManager } from '../../persona.js';

const TEST_MNEMONIC =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

/** 必須項目がすべて妥当な最小メタデータ。 */
function baseMetadata(id: string, index: number): Record<string, unknown> {
  return {
    id,
    index,
    did: `did:key:z${id}`,
    address: '0x0000000000000000000000000000000000000000',
    derivationPath: `m/44'/60'/${index}'/0/0`,
    createdAt: 1_000 + index,
    lastUsedAt: 1_000 + index,
  };
}

/** 指定メタデータを storage へ直接書き込んだ manager を返す（decode の実経路を通す）。 */
async function managerWith(records: Record<string, unknown>[]): Promise<PersonaManager> {
  const storage = new MemoryStorage();
  for (const record of records) {
    await storage.set(
      `persona/${record.id as string}`,
      new TextEncoder().encode(JSON.stringify(record)),
    );
  }
  const km = new KeyManager();
  await km.importMnemonic(TEST_MNEMONIC);
  let clock = 1_000;
  return new PersonaManager(km, storage, createDidKey, () => clock++);
}

describe('persona メタデータ decode の型検証', () => {
  it('label がオブジェクトでも label ソートが TypeError にならず 2005 になる', async () => {
    // 比較の**両辺**が必要（1 件だけだと比較関数が呼ばれずトートロジーになる）。
    const manager = await managerWith([
      { ...baseMetadata('p1', 0), label: 'work' },
      { ...baseMetadata('p2', 1), label: {} },
    ]);

    const error = await manager.listPersonas({ sortBy: 'label' }).then(
      () => undefined,
      (e: unknown) => e,
    );

    // 修正前は `'work'.localeCompare(<null-proto>)` の引数側 ToString で TypeError が漏れていた。
    expect(error).not.toBeInstanceOf(TypeError);
    expect(error).toBeInstanceOf(VericertsError);
    expect((error as VericertsError).code).toBe(ErrorCodes.PERSONA_NOT_FOUND);
  });

  it('妥当な label は従来どおり昇順に並ぶ（正常系）', async () => {
    const manager = await managerWith([
      { ...baseMetadata('p1', 0), label: 'work' },
      { ...baseMetadata('p2', 1), label: 'private' },
      baseMetadata('p3', 2),
    ]);

    const listed = await manager.listPersonas({ sortBy: 'label' });

    // label 未設定は空文字として比較されるため先頭に来る。
    expect(listed.map((p) => p.label)).toEqual([undefined, 'private', 'work']);
  });
});
