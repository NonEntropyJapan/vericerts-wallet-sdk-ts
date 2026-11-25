import assert from 'node:assert/strict';
import { git, listRepoFiles } from '../lib/repo-files.mjs';
import { checkTestResults, expectedTestFiles } from '../lib/result-gate/check.mjs';
import {
  COMMITTED_PROJECTION,
  requireValidationOrigin,
} from '../packed-consumer/source-origin.mjs';

export function createSuiteManifest(files, source) {
  if (!source || !/^[a-f0-9]{40}$/.test(source.revision) || !/^[a-f0-9]{40}$/.test(source.tree))
    throw new Error('Exact SDK source identity is required');
  requireValidationOrigin(source.validationOrigin);
  if (new Set(files).size !== files.length || !files.length)
    throw new Error('SDK test manifest must be nonempty and unique');
  const suites = { source: [], packageInterop: [] };
  for (const file of [...files].sort()) {
    if (file.startsWith('/') || file.split('/').includes('..'))
      throw new Error('SDK test file escapes workspace');
    suites[file.startsWith('test/interop/') ? 'packageInterop' : 'source'].push(file);
  }
  if (!suites.source.length) throw new Error('SDK source suite must be nonempty');
  return {
    version: 1,
    context: 'private-validation',
    source,
    files: [...files].sort(),
    suites,
    scope: suites.packageInterop.length ? 'source-and-package-interop' : 'source-core-only',
  };
}

export function currentSuiteManifest(cwd, validationOrigin = COMMITTED_PROJECTION) {
  const prefix = git(cwd, ['rev-parse', '--show-prefix']).trim().replace(/\/$/, '');
  return createSuiteManifest(expectedTestFiles(listRepoFiles(cwd), '', ['node_modules']), {
    revision: git(cwd, ['rev-parse', 'HEAD']).trim(),
    tree: git(cwd, ['rev-parse', prefix ? `HEAD:${prefix}` : 'HEAD^{tree}']).trim(),
    validationOrigin,
  });
}

export function requireStableSuite(cwd, manifest) {
  assert.equal(
    git(cwd, ['status', '--porcelain', '--untracked-files=all', '--', '.']),
    '',
    'SDK test inputs must be fixed in a clean projection or snapshot',
  );
  const actual = currentSuiteManifest(cwd, manifest.source.validationOrigin);
  assert.deepEqual(actual.source, manifest.source, 'SDK test input revision or tree changed');
  return validateSuiteManifest(manifest, actual.files);
}

// Build both local manifests and received proofs with the same classification.
export function validateSuiteManifest(manifest, files = manifest.files) {
  const canonical = createSuiteManifest(files, manifest.source);
  assert.deepEqual(
    manifest.files,
    canonical.files,
    'Suite manifest omits/duplicates tracked SDK test files',
  );
  assert.deepEqual(
    manifest.suites,
    canonical.suites,
    'SDK suites overlap, omit, or misclassify tracked test files',
  );
  assert.equal(
    manifest.scope,
    canonical.scope,
    'SDK suite scope differs from canonical classification',
  );
  assert.equal(manifest.version, canonical.version, 'Unsupported SDK suite manifest version');
  assert.equal(manifest.context, canonical.context, 'Invalid SDK suite manifest context');
  return canonical;
}

export function validateSuiteResults(manifest, fragments) {
  const canonical = validateSuiteManifest(manifest);
  const seen = new Set();
  const problems = [];
  for (const fragment of fragments) {
    if (
      !Object.hasOwn(canonical.suites, fragment.suite) ||
      fragment.source?.revision !== canonical.source.revision ||
      fragment.source?.tree !== canonical.source.tree ||
      fragment.source?.validationOrigin !== canonical.source.validationOrigin
    )
      throw new Error('Suite result belongs to another SDK source');
    if (
      !Array.isArray(fragment.report?.cases) ||
      fragment.report.cases.some(
        (item) =>
          typeof item.file !== 'string' ||
          !['passed', 'failed', 'skipped', 'todo'].includes(item.status),
      )
    )
      throw new Error('Invalid SDK suite result');
    const expected = canonical.suites[fragment.suite];
    const actual = new Set([
      ...fragment.report.files,
      ...fragment.report.cases.map((item) => item.file),
    ]);
    for (const file of actual) {
      if (!expected.includes(file))
        problems.push(`Unexpected ${fragment.suite} result file: ${file}`);
      if (seen.has(file)) problems.push(`Duplicate SDK suite file: ${file}`);
      seen.add(file);
    }
    problems.push(
      ...checkTestResults(fragment.report, {
        expectedFiles: [...actual].filter((file) => expected.includes(file)),
        label: fragment.suite,
      }),
    );
  }
  for (const file of canonical.files)
    if (!seen.has(file)) problems.push(`Missing SDK suite file: ${file}`);
  if (problems.length) throw new Error(problems.join('\n'));
  return { complete: true, scope: canonical.scope, files: seen.size };
}
