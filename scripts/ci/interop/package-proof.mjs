import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { lstatSync, readdirSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { COMMITTED_PROJECTION } from '../../packed-consumer/source-origin.mjs';
import { verifyInteropCases } from './case-contract.mjs';
import { interopGroups } from './groups.mjs';
import { inventoryInteropHarness } from './harness.mjs';
import { readInteropGroup } from './reports.mjs';
import { interopInvocation } from './run-groups.mjs';

export function verifyPackageProof(
  proof,
  { manifest, workspace, subject, validation, reportsDirectory },
) {
  assert.equal(proof.version, 1, 'Unsupported package Interop proof');
  assert.equal(proof.suite, 'packageInterop');
  assert.ok(['ci-validated', 'local-suite'].includes(validation));
  assert.equal(proof.validationTier, validation, 'Package Interop tier differs');
  assert.deepEqual(proof.source, manifest.source, 'Package Interop source identity differs');
  if (validation === 'ci-validated')
    assert.equal(proof.source.validationOrigin, COMMITTED_PROJECTION);
  assert.deepEqual(
    proof.artifact,
    {
      sha256: subject.tarballSha256,
      integrity: subject.integrity,
      receiptSha256: subject.receiptSha256,
    },
    'Package Interop evidence belongs to another artifact',
  );
  assert.deepEqual(
    proof.harness,
    {
      ...inventoryInteropHarness(workspace),
      sdkSourceTree: manifest.source.tree,
    },
    'Package Interop harness inputs changed',
  );
  assert.deepEqual(
    proof.report.files,
    manifest.suites.packageInterop,
    'Package Interop file set changed',
  );
  assert.equal(proof.report.declaredTests, proof.report.cases.length);
  assert.deepEqual(
    proof.caseParity,
    verifyInteropCases(proof.report.cases),
    'Package Interop identities changed',
  );
  assert.deepEqual(
    proof.groups.map(({ id }) => id),
    interopGroups.map(({ id }) => id),
  );
  const consumer = proof.internalLoop.cwd;
  assert.ok(
    path.isAbsolute(consumer) && path.normalize(consumer) === consumer,
    'Invalid Interop consumer path',
  );
  const directory = path.join(consumer, 'coverage/interop');
  const bun = readFileSync(path.join(workspace, '.bun-version'), 'utf8').trim();
  const observedCases = [];
  const observedReports = [];
  assert.deepEqual(
    proof.internalLoop,
    {
      runtime: 'bun',
      version: bun,
      argv: [
        '--preload',
        path.join(consumer, 'scripts/packed-consumer/preload-bun.mjs'),
        'test/interop/run-internal-loop.mjs',
      ],
      cwd: consumer,
      exitCode: 0,
    },
    'Expected the real Internal Loop to succeed',
  );
  for (const [i, group] of interopGroups.entries()) {
    const actual = proof.groups[i];
    const invocation = interopInvocation(group, consumer, directory);
    assert.equal(actual.runtime, group.runtime);
    assert.equal(actual.cwd, consumer);
    assert.equal(actual.exitCode, 0);
    if (group.runtime === 'bun') assert.equal(actual.version, bun);
    else assert.match(actual.version, /^24\.\d+\.\d+$/);
    assert.deepEqual(actual.files, [...group.targets].sort());
    assert.equal(
      actual.leafCases,
      proof.report.cases.filter(
        (x) => group.targets.includes(x.file) && x.runtime === group.runtime,
      ).length,
    );
    assert.ok(actual.leafCases > 0);
    assert.deepEqual(Object.keys(actual.reports).sort(), Object.keys(invocation.reports).sort());
    assert.ok(Object.values(actual.reports).every((hash) => /^[a-f0-9]{64}$/.test(hash)));
    assert.deepEqual(actual.argv, invocation.args);
    const reportPaths = Object.fromEntries(
      Object.entries(invocation.reports).map(([type, file]) => {
        const name = path.basename(file);
        const location = path.join(reportsDirectory, name);
        assert.ok(lstatSync(location).isFile(), 'Interop raw evidence must be a regular file');
        const hash = createHash('sha256').update(readFileSync(location)).digest('hex');
        assert.equal(actual.reports[type], hash, 'Interop raw evidence changed');
        observedReports.push(name);
        return [type, location];
      }),
    );
    observedCases.push(...readInteropGroup({ group, consumer, ...reportPaths }).cases);
  }
  assert.deepEqual(readdirSync(reportsDirectory).sort(), observedReports.sort());
  assert.deepEqual(
    observedCases,
    proof.report.cases,
    'Interop case identities differ from raw evidence',
  );
}
