import { describe, expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import pkg from '../../../../package.json' with { type: 'json' };
import { PURPOSE_ENTRIES } from './purpose-entries.fixtures';

/**
 * 用途別 entry（`./aa` … `./trust` の 12 本）の exports マップと build 配線の契約を固定する回帰テスト。
 * 公開シンボルの検査は `purpose-subpath-surface.test.ts` が担う。
 * 実成果物での解決・クラス同一性は `scripts/smoke-node.{mjs,cjs}` が検証する。
 */
describe('purpose-built subpath contract: exports map and build wiring', () => {
  test('exports map declares exactly the main, experimental, otel, 12 entries and package.json', () => {
    expect(Object.keys(pkg.exports).sort()).toEqual(
      [
        '.',
        './experimental',
        './experimental/eudi',
        './experimental/oid4vci',
        './otel',
        './package.json',
        ...PURPOSE_ENTRIES.map((name) => `./${name}`),
      ].sort(),
    );
  });

  for (const name of PURPOSE_ENTRIES) {
    test(`exports map declares ./${name} with types first and ESM/CJS/d.ts targets`, () => {
      const sub =
        (pkg.exports as unknown as Record<string, Record<string, unknown>>)[`./${name}`] ?? {};
      expect(Object.keys(sub)).toEqual(['types', 'import', 'require', 'default']);
      expect(sub.types).toEqual({
        import: `./dist/exports/${name}.d.ts`,
        require: `./dist/cjs-types/exports/${name}.d.ts`,
        default: `./dist/exports/${name}.d.ts`,
      });
      expect(sub.import).toBe(`./dist/exports/${name}.js`);
      expect(sub.require).toBe(`./dist/exports/${name}.cjs`);
      expect(sub.default).toBe(`./dist/exports/${name}.js`);
    });

    test(`./${name} is built by ESM, CJS (shared bundle) and the declaration build`, () => {
      expect(pkg.scripts['build:js']).toContain(`./src/exports/${name}.ts`);
      const cjsEntry = readFileSync(new URL('../../../cjs-entry.ts', import.meta.url), 'utf8');
      expect(cjsEntry).toContain(`import * as ${name}Ns from './exports/${name}.js';`);
      expect(cjsEntry).toContain(`export const ${name} = { ...${name}Ns };`);
      const pickers = readFileSync(
        new URL('../../../../scripts/emit-cjs-pickers.mjs', import.meta.url),
        'utf8',
      );
      const surfaces = pickers.match(/const SUBPATH_SURFACES = \[([^\]]*)\]/)?.[1] ?? '';
      expect(surfaces).toContain(`'${name}',`);
      const tsconfig = readFileSync(
        new URL('../../../../tsconfig.build.json', import.meta.url),
        'utf8',
      );
      expect(tsconfig).toContain(`"src/exports/${name}.ts"`);
    });
  }

  for (const name of ['eudi', 'oid4vci'] as const) {
    test(`./experimental/${name} has ESM, CJS and declaration targets`, () => {
      const target = `./dist/exports/experimental/${name}`;
      const entry = (pkg.exports as unknown as Record<string, Record<string, unknown>>)[
        `./experimental/${name}`
      ];
      expect(entry).toEqual({
        types: {
          import: `${target}.d.ts`,
          require: `./dist/cjs-types/exports/experimental/${name}.d.ts`,
          default: `${target}.d.ts`,
        },
        import: `${target}.js`,
        require: `${target}.cjs`,
        default: `${target}.js`,
      });
      expect(pkg.scripts['build:js']).toContain(`./src/exports/experimental/${name}.ts`);
      const cjs = readFileSync(new URL('../../../cjs-entry.ts', import.meta.url), 'utf8');
      const surface = `experimental${name[0]?.toUpperCase()}${name.slice(1)}`;
      expect(cjs).toContain(`export const ${surface} = { ...${surface}Ns };`);
      const tsconfig = readFileSync(
        new URL('../../../../tsconfig.build.json', import.meta.url),
        'utf8',
      );
      expect(tsconfig).toContain(`"src/exports/experimental/${name}.ts"`);
    });
  }

  test('the shared CJS entry exposes no surface beyond the exports map (otel stays out)', () => {
    const cjsEntry = readFileSync(new URL('../../../cjs-entry.ts', import.meta.url), 'utf8');
    const surfaces = [...cjsEntry.matchAll(/^export const (\w+) = \{/gm)].map((m) => m[1]);
    expect(surfaces.sort()).toEqual(
      [
        'main',
        'experimental',
        'experimentalEudi',
        'experimentalOid4vci',
        ...PURPOSE_ENTRIES,
      ].sort(),
    );
  });
});
