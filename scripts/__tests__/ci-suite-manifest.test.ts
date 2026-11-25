import { describe, expect, test } from 'bun:test';
import {
  createSuiteManifest,
  validateSuiteManifest,
  validateSuiteResults,
} from '../ci/suite-manifest.mjs';

const source = {
  revision: 'a'.repeat(40),
  tree: 'b'.repeat(40),
  validationOrigin: 'committed-projection',
};
const files = [
  'src/core.test.ts',
  ...Array.from({ length: 29 }, (_, i) => `test/interop/case-${i}.test.mjs`),
];
const manifest = createSuiteManifest(files, source);
const fragment = (suite: 'source' | 'packageInterop', selected = manifest.suites[suite]) => ({
  suite,
  source,
  report: {
    cases: selected.map((file) => ({ file, name: 'case', status: 'passed' })),
    files: new Set(selected),
    declaredTests: selected.length,
  },
});
describe('source and packaged Interop execution union', () => {
  test('requires all tracked files across the two suites without mixing coverage', () => {
    expect(
      validateSuiteResults(manifest, [fragment('source'), fragment('packageInterop')]),
    ).toEqual({ complete: true, scope: 'source-and-package-interop', files: 30 });
    const core = createSuiteManifest(['src/core.test.ts'], source);
    expect(validateSuiteResults(core, [fragment('source')]).scope).toBe('source-core-only');
  });
  test('rejects missing/duplicate/omitted suite file and different source', () => {
    expect(() => validateSuiteResults(manifest, [fragment('source')])).toThrow('Missing');
    expect(() =>
      validateSuiteResults(manifest, [
        fragment('source'),
        fragment('packageInterop', files.slice(1, 29)),
      ]),
    ).toThrow('Missing');
    expect(() =>
      validateSuiteResults(manifest, [
        fragment('source'),
        fragment('source'),
        fragment('packageInterop'),
      ]),
    ).toThrow('Duplicate');
    expect(() =>
      validateSuiteResults({ ...manifest, suites: { ...manifest.suites, source: [] } }, [
        fragment('packageInterop'),
      ]),
    ).toThrow('omit');
    expect(() =>
      validateSuiteResults(manifest, [
        { ...fragment('source'), source: { ...source, tree: 'c'.repeat(40) } },
      ]),
    ).toThrow('another SDK');
  });
  test('rejects a noncanonical partition even if all reported files are present', () => {
    const packagedAsSource = {
      ...manifest,
      scope: 'source-core-only',
      suites: { source: manifest.files, packageInterop: [] },
    };
    expect(() =>
      validateSuiteResults(packagedAsSource, [fragment('source', manifest.files)]),
    ).toThrow('misclassify');

    const twoCore = createSuiteManifest([...files, 'src/extra.test.ts'], source);
    const sourceAsPackaged = {
      ...twoCore,
      suites: {
        source: manifest.suites.source,
        packageInterop: ['src/extra.test.ts', ...manifest.suites.packageInterop].sort(),
      },
    };
    expect(() =>
      validateSuiteResults(sourceAsPackaged, [
        fragment('source'),
        fragment('packageInterop', sourceAsPackaged.suites.packageInterop),
      ]),
    ).toThrow('misclassify');
  });

  test('checks the received manifest against the file inventory and its derived metadata', () => {
    const received = JSON.parse(JSON.stringify(manifest));
    expect(validateSuiteManifest(received, files)).toEqual(manifest);
    expect(() => validateSuiteManifest(received, [...files, 'src/other.test.ts'])).toThrow(
      'tracked SDK test files',
    );
    for (const [change, message] of [
      [{ scope: 'source-core-only' }, 'scope'],
      [{ version: 2 }, 'version'],
      [{ context: 'public' }, 'context'],
    ] as const)
      expect(() =>
        validateSuiteResults({ ...received, ...change }, [
          fragment('source'),
          fragment('packageInterop'),
        ]),
      ).toThrow(message);
  });

  test('rejects unexpected files, partial result counts and skip/todo/failure/zero', () => {
    for (const status of ['failed', 'skipped', 'todo']) {
      const bad = fragment('source');
      bad.report.cases[0].status = status;
      expect(() => validateSuiteResults(manifest, [bad, fragment('packageInterop')])).toThrow();
    }
    const partial = fragment('packageInterop');
    partial.report.declaredTests += 1;
    expect(() => validateSuiteResults(manifest, [fragment('source'), partial])).toThrow('件数');
    expect(() =>
      validateSuiteResults(manifest, [
        fragment('source'),
        fragment('packageInterop', ['test/interop/not-tracked.test.mjs']),
      ]),
    ).toThrow('Unexpected');
    expect(() =>
      validateSuiteResults(manifest, [
        {
          ...fragment('source'),
          report: { cases: [], files: new Set(['src/core.test.ts']), declaredTests: 0 },
        },
        fragment('packageInterop'),
      ]),
    ).toThrow();
    expect(() => createSuiteManifest([], source)).toThrow('nonempty');
    expect(() => createSuiteManifest(['src/core.test.ts', 'src/core.test.ts'], source)).toThrow(
      'unique',
    );
  });
});
