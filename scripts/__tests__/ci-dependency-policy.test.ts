import { afterAll, describe, expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import { dependencyProblems } from '../ci/dependency-policy.mjs';
import { fixture } from './gates-fixture';

const f = fixture();
afterAll(() => f.close());
const original = JSON.parse(f.read('package.json'));

test('permits only the locked Sphereon peer override tuple', () => {
  const file = 'test/interop/adapters/sphereon/package.json';
  const lockSha256 = '54b8dba72ed99d641bb39fb3750e3849aa029fa0011148c6b6adde78e370f944';
  const pkg = JSON.parse(
    readFileSync(
      new URL('../../test/interop/adapters/sphereon/package.json', import.meta.url),
      'utf8',
    ),
  );
  const selector = '@veramo-community/lds-ecdsa-secp256k1-recovery2020';
  const valid = { file, lockSha256 };
  expect(dependencyProblems(pkg, valid)).toEqual([]);
  for (const candidate of [
    [pkg, undefined],
    [pkg, { ...valid, file: `other/${file}` }],
    [pkg, { ...valid, lockSha256: '0'.repeat(64) }],
    [{ ...pkg, name: 'other-peer' }, valid],
    [{ ...pkg, private: false }, valid],
    [{ ...pkg, overrides: {} }, valid],
    [{ ...pkg, overrides: { altered: pkg.overrides[selector] } }, valid],
    [{ ...pkg, overrides: { [selector]: 'git+https://example.invalid/peer.git#main' } }, valid],
    [{ ...pkg, overrides: { ...pkg.overrides, another: 'file:../outside' } }, valid],
  ] as const)
    expect(dependencyProblems(...candidate)).not.toEqual([]);
});
const cli = (extra: unknown) => {
  f.write('package.json', JSON.stringify({ ...original, ...extra }));
  return f.node('scripts/ci/source-boundary.mjs');
};
const invalid = [
  'file:../../private',
  'link:../private',
  'portal:../private',
  'patch:dep@1#./patch',
  '../private',
  './private',
  '/private/pkg',
  'C:\\private\\pkg',
  '\\\\server\\pkg',
  '~/private',
  'workspace:^1',
  'catalog:default',
  'git://example.invalid/pkg',
  'git+ssh://git@example.invalid/pkg',
  'git@example.invalid:owner/repo.git',
  'github:owner/repo',
  'gitlab:owner/repo',
  'bitbucket:owner/repo',
  'owner/repo#main',
  'https://example.invalid/pkg.tgz',
  'http://example.invalid/pkg.tgz',
  '*',
  'x',
  '',
  '1 || *',
  ' || ^1',
  'npm:other@*',
  'npm:other@file:../private',
  'unknown-scheme:payload',
  'archive.tgz',
  'archive.tar.gz',
  '>=0.0.0',
  'npm:other',
];
describe('SDK registry-only dependency declarations', () => {
  test('preserves registry versions/ranges/tags and constrained npm aliases', () => {
    for (const spec of [
      '1.2.3',
      '^1.2.3',
      '~1.2',
      '>=1 <2',
      '1.x',
      '1.2',
      'latest',
      'next',
      'beta',
      'npm:other@^1',
      'npm:@scope/other@beta',
    ])
      expect(dependencyProblems({ dependencies: { dep: spec } })).toEqual([]);
    expect(
      dependencyProblems({
        dependencies: { dep: '^1', other: '^2' },
        overrides: { dep: { '.': '$dep', other: '$other' } },
        pnpm: { overrides: { dep: '$dep' } },
        resolutions: { dep: '^1' },
      }),
    ).toEqual([]);
  }, 30_000);
  test('rejects every nonregistry or unbounded form across all four dependency fields', () => {
    for (const field of [
      'dependencies',
      'devDependencies',
      'peerDependencies',
      'optionalDependencies',
    ])
      for (const spec of invalid)
        expect(dependencyProblems({ [field]: { dep: spec } }).length).toBeGreaterThan(0);
    for (const value of [[], null, 42, true, { dep: {} }, { dep: [] }])
      expect(dependencyProblems({ dependencies: value }).length).toBeGreaterThan(0);
  }, 30_000);
  test('inspects nested replacements, pnpm additions and rejects unresolved/cyclic references', () => {
    for (const pkg of [
      { overrides: { dep: { child: { '.': 'file:../private' } } } },
      { resolutions: { dep: 'owner/repo#main' } },
      { pnpm: { overrides: { dep: 'bitbucket:owner/repo' } } },
      {
        pnpm: {
          packageExtensions: { 'dep@1': { optionalDependencies: { child: 'file:../private' } } },
        },
      },
      { overrides: { dep: '$missing' } },
      { dependencies: { dep: '$other', other: '$dep' }, overrides: { dep: '$other' } },
      { overrides: { dep: '$other', other: '$dep' } },
      { overrides: ['1.0.0'] },
      { workspaces: ['packages/*'] },
      { catalog: { dep: '^1' } },
      { bundleDependencies: ['dep'] },
    ])
      expect(dependencyProblems(pkg).length).toBeGreaterThan(0);
  }, 30_000);
  test('actual CLI rejects all review reproductions and deep replacement variants', () => {
    for (const extra of [
      { dependencies: { foo: 'owner/repo#main' } },
      { dependencies: { foo: 'bitbucket:owner/repo' } },
      { optionalDependencies: { foo: 'file:../../private' } },
      { overrides: { typescript: 'file:../../private' } },
      { overrides: { parent: { child: 'file:../../private' } } },
      { pnpm: { overrides: { foo: 'file:../../private' } } },
      { resolutions: { foo: 'unknown:private' } },
    ]) {
      const result = cli(extra);
      expect(result.status).toBe(1);
      expect(result.output).toContain('nonregistry');
    }
    expect(cli({ dependencies: { dep: 'npm:other@^1' }, overrides: { dep: '$dep' } }).status).toBe(
      0,
    );
  }, 30_000);
});
