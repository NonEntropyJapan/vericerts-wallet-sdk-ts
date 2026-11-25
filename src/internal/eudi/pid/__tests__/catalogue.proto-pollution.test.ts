/**
 * `createRecordCatalogueSource` の own 限定読み取りの回帰テスト
 * （`eudi/wua/wua.ts` の `verifyWalletUnitAttestation` と同クラス）。
 *
 * `catalogue[vct]` と `entry.vct === vct` はどちらもプロトタイプ鎖を辿っていた。`catalogue` は
 * **呼び出し側が組み立てて渡す対応表**であり、パース境界を
 * 通らないため、次の 2 つの fail-open が成立した。
 *
 * 1. `catalogue[vct]`: `vct` が `toString` / `constructor` のような `Object.prototype` のメンバ名
 *    だと、**未登録の vct に対して `Object.prototype` のメンバが引ける**（外部由来の鍵で引く
 *    対応表の問題）。ただし
 *    それ単独では直後の `entry.vct === vct` 突合が弾くため、実際に「登録済みエントリ」として
 *    通るのは **`Object.prototype.vct = 'toString'` の汚染と併用したとき**である。
 * 2. `entry.vct`: own に `vct` を持たないエントリが `Object.prototype.vct` の汚染値を拾い、
 *    **キーと中身が食い違うエントリが突合を通過する**。この突合はまさにそれを防ぐための検査で、
 *    鎖読みだと検査そのものが無効化される。
 *
 * **トートロジー回避**: 汚染値と own 値を食い違わせ、正当な引きが従来どおり成功する対照も置く。
 */

import { describe, expect, it } from 'bun:test';
import { withPollutedPrototype } from '../../../__tests__/prototype-pollution.fixtures.js';
import { createRecordCatalogueSource } from '../catalogue.js';
import { type AttestationCatalogueEntry, PID_VCT } from '../types.js';

const pidEntry: AttestationCatalogueEntry = {
  vct: PID_VCT,
  rulebookUrl: 'https://arf.ec.europa.eu/rulebooks/pid.md',
  schemaUrl: 'https://arf.ec.europa.eu/schemas/pid.schema.json',
  version: '1.5',
};

describe('createRecordCatalogueSource の引きと突合は own 限定', () => {
  it('Object.prototype のメンバ名で引いても登録済みとして返らない（vct 汚染と併用）', () => {
    const source = createRecordCatalogueSource({ [PID_VCT]: pidEntry });

    // 汚染単独・鍵単独では修正前も弾かれる（`entry.vct`(=undefined) !== 'toString'）。
    // 両方を組み合わせたときだけ修正前の実装が破れるため、この形で回帰を固定する。
    const found = withPollutedPrototype({ vct: 'toString' }, () => source.lookup('toString'));

    expect(found).toBeUndefined();
  });

  it('対照: 汚染なしでも Object.prototype のメンバ名は未登録扱い', () => {
    const source = createRecordCatalogueSource({ [PID_VCT]: pidEntry });

    expect(source.lookup('toString')).toBeUndefined();
    expect(source.lookup('constructor')).toBeUndefined();
    expect(source.lookup('hasOwnProperty')).toBeUndefined();
  });

  it('own の値が null のエントリは生の TypeError にせず未登録扱いにする', () => {
    const source = createRecordCatalogueSource({
      [PID_VCT]: null as unknown as AttestationCatalogueEntry,
    });

    expect(() => source.lookup(PID_VCT)).not.toThrow();
    expect(source.lookup(PID_VCT)).toBeUndefined();
  });

  it('own に vct を持たないエントリは汚染値で突合を通過しない', () => {
    // own の vct を落としたエントリ。鎖読みだと汚染値がキーと一致して「登録済み」になる。
    const broken = { ...pidEntry } as Record<string, unknown>;
    delete broken.vct;
    const source = createRecordCatalogueSource({
      [PID_VCT]: broken as unknown as AttestationCatalogueEntry,
    });

    const found = withPollutedPrototype({ vct: PID_VCT }, () => source.lookup(PID_VCT));

    expect(found).toBeUndefined();
  });

  it('対照: 正当なエントリは汚染下でも従来どおり引ける', () => {
    const source = createRecordCatalogueSource({ [PID_VCT]: pidEntry });

    const found = withPollutedPrototype({ vct: 'urn:attacker:vct' }, () => source.lookup(PID_VCT));

    expect(found).toBe(pidEntry);
  });

  it('対照: キーと中身の vct が食い違うエントリは従来どおり未登録扱い', () => {
    const source = createRecordCatalogueSource({
      'urn:eudi:mdl:1': pidEntry,
    });

    expect(source.lookup('urn:eudi:mdl:1')).toBeUndefined();
  });
});
