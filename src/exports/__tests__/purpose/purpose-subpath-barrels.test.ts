import { describe, expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import * as sdk from '../../../index';
import { createPresentation as createPresentationImpl } from '../../../internal/auth/create-presentation/index';
import * as aaEntry from '../../aa';
import * as commonEntry from '../../common';
import * as errorsEntry from '../../errors';
import * as oid4vciEntry from '../../oid4vci';
import * as oid4vpEntry from '../../oid4vp';
import {
  COMMON_SUBPATH_ONLY_VALUES,
  PURPOSE_ENTRY_VALUES,
  PURPOSE_SUBPATH_ONLY_VALUES,
} from './purpose-entries.fixtures';
import { SUBPATH_ONLY_ENTRY_TYPES } from './purpose-entry-types.fixtures';

/**
 * サブパス専用の用途別 entry（`./common` / `./oid4vci` / `./oid4vp` をサブパスごとに公開）の契約。
 * `/common`、`/oid4vp`、`/oid4vci` の追加値と /aa はメインバレルへ流さない。
 */

const SUBPATH_ONLY_ENTRIES = ['aa', 'common', 'oid4vci', 'oid4vp'] as const;

const entries = { aa: aaEntry, common: commonEntry, oid4vci: oid4vciEntry, oid4vp: oid4vpEntry };

const readExportsFile = (file: string): string =>
  readFileSync(new URL(`../../${file}`, import.meta.url), 'utf8');

/** ブロックコメントと行コメントを除去する（コメント内の `export ... from` を拾わないため）。 */
const stripComments = (source: string): string =>
  source.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');

/** 明示的な再公開と型 alias から公開名を取り出す。 */
const exportedNames = (source: string): string[] => [
  ...[...stripComments(source).matchAll(/export (?:type )?\{([^}]*)\} from/g)]
    .flatMap((m) => (m[1] ?? '').split(','))
    .map((name) => name.trim().replace(/^type /, ''))
    .filter(Boolean),
  ...[...stripComments(source).matchAll(/export type (\w+) =/g)].map((m) => m[1] ?? ''),
];

describe('subpath-only barrels', () => {
  const expectedCounts = { aa: 5, common: 30, oid4vci: 32, oid4vp: 24 };

  for (const name of SUBPATH_ONLY_ENTRIES) {
    test(`./${name} exports exactly the expected symbols (values + types = ${expectedCounts[name]})`, () => {
      const expected = [...PURPOSE_ENTRY_VALUES[name], ...SUBPATH_ONLY_ENTRY_TYPES[name]];
      expect(exportedNames(readExportsFile(`${name}.ts`)).sort()).toEqual([...expected].sort());
      expect(expected).toHaveLength(expectedCounts[name]);
    });

    test(`./${name} exposes only its assigned additions`, () => {
      const names = exportedNames(readExportsFile(`${name}.ts`));
      expect(names.includes('fetchWellKnownJson')).toBe(name === 'common');
      expect(names.includes('createPresentation')).toBe(name === 'oid4vp');
    });

    test(`./${name} has no wildcard re-export (export * / export type *)`, () => {
      expect(stripComments(readExportsFile(`${name}.ts`))).not.toMatch(/export\s+(?:type\s+)?\*/);
    });
  }

  test('reused values share the main barrel reference; additions remain subpath-only', () => {
    const mainNames = new Set(Object.keys(sdk));
    for (const name of SUBPATH_ONLY_ENTRIES) {
      for (const symbol of PURPOSE_ENTRY_VALUES[name]) {
        if (
          name === 'aa' ||
          (name === 'common' && COMMON_SUBPATH_ONLY_VALUES.includes(symbol)) ||
          (name === 'oid4vp' &&
            PURPOSE_SUBPATH_ONLY_VALUES.oid4vp.some((value) => value === symbol)) ||
          (name === 'oid4vci' &&
            ['resolvePreAuthorizedTokenEndpoint', 'resolveProofNonce'].includes(symbol))
        ) {
          expect(mainNames.has(symbol)).toBe(false);
          continue;
        }
        expect(mainNames.has(symbol)).toBe(true);
        expect((sdk as Record<string, unknown>)[symbol]).toBe(
          (entries[name] as Record<string, unknown>)[symbol],
        );
      }
    }
  });

  test('./oid4vp exposes the parsed-request presentation implementation', () => {
    expect(oid4vpEntry.createPresentation).toBe(createPresentationImpl);
  });

  test('./oid4vp keeps DcqlWorkBudget as the existing mutable WorkBudget alias', () => {
    const source = readExportsFile('oid4vp.ts');
    expect(source).toContain(
      "import type { WorkBudget } from '../internal/primitives/work-budget.js';",
    );
    expect(source).toContain('export type DcqlWorkBudget = WorkBudget;');
  });

  test('./common shares VericertsError and ErrorCodes with the errors barrel and main', () => {
    expect(commonEntry.VericertsError).toBe(errorsEntry.VericertsError);
    expect(commonEntry.ErrorCodes).toBe(errorsEntry.ErrorCodes);
    expect(commonEntry.VericertsError).toBe(sdk.VericertsError);
    expect(commonEntry.ErrorCodes).toBe(sdk.ErrorCodes);
  });
});
