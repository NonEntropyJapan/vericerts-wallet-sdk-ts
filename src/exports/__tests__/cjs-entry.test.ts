import { describe, expect, test } from 'bun:test';
import * as cjsEntry from '../../cjs-entry';
import * as sdk from '../../index';
import * as aa from '../aa';
import * as asset from '../asset';
import * as common from '../common';
import * as credential from '../credential';
import * as eudi from '../eudi';
import * as experimental from '../experimental';
import * as experimentalEudi from '../experimental/eudi';
import * as experimentalOid4vci from '../experimental/oid4vci';
import * as gdpr from '../gdpr';
import * as identity from '../identity';
import * as keymanager from '../keymanager';
import * as oid4vci from '../oid4vci';
import * as oid4vp from '../oid4vp';
import * as persona from '../persona';
import * as trust from '../trust';
import { PURPOSE_ENTRIES } from './purpose/purpose-entries.fixtures';

/**
 * `src/cjs-entry.ts`（CJS 共有バンドル `dist/_shared.cjs` のエントリ）の契約。
 * 各サーフェスは対応するバレルの公開名をすべて含み、値は同一参照でなければならない
 * （実体が二重化するとエラークラスの `instanceof` が壊れる）。
 */

const purposeBarrels = {
  aa,
  asset,
  common,
  credential,
  eudi,
  gdpr,
  identity,
  keymanager,
  oid4vci,
  oid4vp,
  persona,
  trust,
};

/**
 * 名前空間オブジェクトを添字で引くと biome の `noDynamicNamespaceImportAccess` が出る
 * （名前空間の動的アクセスはバンドラの最適化を妨げる）。一度だけ素の record へ移して使う。
 */
const cjsSurfaces = cjsEntry as unknown as Record<string, Record<string, unknown>>;

const surfaces: Record<string, [surface: object, barrel: object]> = {
  main: [cjsEntry.main, sdk],
  experimental: [cjsEntry.experimental, experimental],
  experimentalEudi: [cjsEntry.experimentalEudi, experimentalEudi],
  experimentalOid4vci: [cjsEntry.experimentalOid4vci, experimentalOid4vci],
  ...Object.fromEntries(
    PURPOSE_ENTRIES.map((name) => [name, [cjsSurfaces[name], purposeBarrels[name]]]),
  ),
};

describe('cjs-entry surfaces', () => {
  test('用途別 entry 12 本をすべて検査対象にしている', () => {
    expect(PURPOSE_ENTRIES).toHaveLength(12);
    expect(Object.keys(purposeBarrels).sort()).toEqual([...PURPOSE_ENTRIES].sort());
  });

  test.each(Object.entries(surfaces))('%s は対応バレルの公開名をすべて含む', (_name, [
    surface,
    barrel,
  ]) => {
    const names = Object.keys(barrel);
    expect(names.length).toBeGreaterThan(0);
    expect(Object.keys(surface)).toEqual(expect.arrayContaining(names));
  });

  test.each(Object.entries(surfaces))('%s の値は対応バレルと同一参照である', (_name, [
    surface,
    barrel,
  ]) => {
    for (const [key, value] of Object.entries(barrel)) {
      expect((surface as Record<string, unknown>)[key]).toBe(value);
    }
  });

  test.each(
    PURPOSE_ENTRIES,
  )('%s の値はメインバレルと同一参照である（実体が二重化しない）', (name) => {
    const mainSurface = cjsEntry.main as Record<string, unknown>;
    const surface = cjsSurfaces[name];
    if (surface === undefined) throw new Error(`cjs-entry に ${name} サーフェスがない`);
    for (const [key, value] of Object.entries(surface)) {
      if (key in mainSurface) expect(value).toBe(mainSurface[key]);
    }
  });

  test('VericertsError はメインと用途別 entry で同一クラスである', () => {
    expect(cjsEntry.common.VericertsError).toBe(cjsEntry.main.VericertsError);
  });

  test('otel のサーフェスを含まない（optional peer を共有バンドルへ引き込まない）', () => {
    expect(Object.keys(cjsEntry).sort()).toEqual(
      [
        'main',
        'experimental',
        'experimentalEudi',
        'experimentalOid4vci',
        ...PURPOSE_ENTRIES,
      ].sort(),
    );
    const otelNames = ['createOtelLogger', 'createOtelMetrics', 'createOtelTracer'];
    for (const [surface] of Object.values(surfaces)) {
      for (const name of otelNames) expect(surface).not.toHaveProperty(name);
    }
  });
});
