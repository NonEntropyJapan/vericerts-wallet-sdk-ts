import assert from 'node:assert/strict';
import { existsSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { basename, join } from 'node:path';
import { digest } from './archive.mjs';
import { run } from './process.mjs';
import { COMMITTED_PROJECTION, requireValidationOrigin } from './source-origin.mjs';

export function sourceIdentity(sdk, expectedSha, validationOrigin) {
  requireValidationOrigin(validationOrigin);
  const sha = run('git', ['rev-parse', 'HEAD'], sdk).trim();
  assert.match(sha, /^[a-f0-9]{40}$/);
  if (expectedSha) assert.ok(sha === expectedSha, 'Source SHA does not match producer');
  const prefix = run('git', ['rev-parse', '--show-prefix'], sdk).replace(/\r?\n$/, '');
  const tree = run('git', ['rev-parse', `HEAD:${prefix.replace(/\/$/, '')}`], sdk).trim();
  const clean =
    run('git', ['status', '--porcelain', '--untracked-files=all', '--', '.'], sdk).trim() === '';
  assert.equal(clean, true, 'SDK inputs must be fixed in a clean source projection or snapshot');
  const sourceSchemas = {};
  for (const name of ['error-codes.json', 'log-entry.json', 'conformance-vectors.json']) {
    sourceSchemas[name] = digest(readFileSync(join(sdk, 'schemas', name)));
  }
  return {
    context: 'private-validation',
    validationOrigin,
    publicRevision: null,
    privateRevision: {
      sha,
      tree,
      clean,
      lockSha256: digest(readFileSync(join(sdk, 'bun.lock'))),
      sourceSchemas,
    },
  };
}

export function readReceipt(path) {
  const receipt = JSON.parse(readFileSync(path, 'utf8'));
  assert.equal(receipt.schemaVersion, 2, 'Unsupported artifact receipt');
  assert.equal(receipt.source?.context, 'private-validation');
  requireValidationOrigin(receipt.source.validationOrigin);
  assert.equal(receipt.source.publicRevision, null, 'Public revision is not approved by this gate');
  assert.match(receipt.source?.privateRevision?.sha, /^[a-f0-9]{40}$/);
  assert.match(receipt.source?.privateRevision?.tree, /^[a-f0-9]{40}$/);
  assert.match(receipt.source?.privateRevision?.lockSha256, /^[a-f0-9]{64}$/);
  assert.equal(typeof receipt.source.privateRevision.clean, 'boolean');
  for (const name of ['error-codes.json', 'log-entry.json', 'conformance-vectors.json']) {
    assert.match(receipt.source.privateRevision.sourceSchemas?.[name], /^[a-f0-9]{64}$/);
  }
  assert.match(receipt.tooling?.typescript, /^\d+\.\d+\.\d+$/);
  assert.ok(Array.isArray(receipt.checks?.node));
  assert.match(receipt.tooling?.bun, /^\d+\.\d+\.\d+$/);
  return receipt;
}

export function assertReceiptArtifact(receipt, artifact, expectedSha) {
  assert.match(expectedSha, /^[a-f0-9]{40}$/, 'Explicit source SHA is required');
  assert.ok(receipt.source.privateRevision.sha === expectedSha, 'Receipt source SHA mismatch');
  const { filename: _filename, ...recorded } = receipt.artifact;
  assert.deepEqual(recorded, artifact, 'Receipt artifact identity/digest mismatch');
}

export function newReceipt(artifact, tarball, source, tooling) {
  requireValidationOrigin(source.validationOrigin);
  return {
    schemaVersion: 2,
    artifact: { ...artifact, filename: basename(tarball) },
    source,
    tooling,
    checks: { node: [], browser: { status: 'not-run' }, bun: { status: 'not-run' } },
    release: { tagNamespace: null, publicProvenance: 'not-established', publishPerformed: false },
  };
}

export function saveReceipt(path, receipt) {
  const staging = `${path}.${process.pid}.tmp`;
  assert.ok(!existsSync(staging), 'Receipt staging path already exists');
  writeFileSync(staging, `${JSON.stringify(receipt, null, 2)}\n`, { flag: 'wx' });
  renameSync(staging, path);
}

export function requireReleaseChecks(receipt) {
  assert.equal(
    requireValidationOrigin(receipt.source.validationOrigin),
    COMMITTED_PROJECTION,
    'Development snapshot is not a release candidate',
  );
  assert.equal(
    receipt.source.privateRevision.clean,
    true,
    'Dirty-source receipt is not a release candidate',
  );
  assert.ok(receipt.checks.node.length > 0, 'No Node consumers were verified');
  assert.ok(
    receipt.checks.node.every((check) => check.status === 'passed'),
    'Incomplete/failed Node consumer',
  );
  for (const version of ['20.19.0', '22.', '24.']) {
    assert.ok(
      receipt.checks.node.some((check) =>
        version.endsWith('.') ? check.version.startsWith(version) : check.version === version,
      ),
      `Missing Node ${version} consumer`,
    );
  }
  for (const check of receipt.checks.node) {
    assert.deepEqual(check.formats, ['esm', 'cjs']);
    assert.equal(check.strictTypeModes, 5);
    assert.deepEqual(check.optionalPeers, ['absent', 'installed']);
  }
  assert.equal(receipt.checks.bun?.status, 'passed', 'Bun consumers were not verified');
  assert.equal(receipt.checks.bun.version, receipt.tooling.bun);
  assert.deepEqual(receipt.checks.bun.formats, ['esm', 'cjs']);
  assert.deepEqual(receipt.checks.bun.optionalPeers, ['absent', 'installed']);
  assert.equal(receipt.checks.browser.status, 'passed', 'Browser consumers were not verified');
  assert.deepEqual(receipt.checks.browser.optionalPeers, ['absent', 'installed']);
  assert.equal(receipt.release.publishPerformed, false);
  assert.equal(receipt.release.publicProvenance, 'not-established');
  assert.equal(receipt.release.tagNamespace, null, 'An artifact receipt cannot assert a Git tag');
}
