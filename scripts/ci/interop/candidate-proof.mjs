import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { listRepoFiles } from '../../lib/repo-files.mjs';
import { expectedTestFiles } from '../../lib/result-gate/check.mjs';
import { COMMITTED_PROJECTION } from '../../packed-consumer/source-origin.mjs';
import { validateSuiteManifest, validateSuiteResults } from '../suite-manifest.mjs';
import { verifyPackageProof } from './package-proof.mjs';

export function verifySuiteProofs(
  directory,
  receipt,
  {
    workspace = fileURLToPath(new URL('../../../', import.meta.url)),
    expectedFiles = expectedTestFiles(listRepoFiles(workspace), '', ['node_modules']),
    subject,
  } = {},
) {
  const manifest = JSON.parse(
    readFileSync(path.join(directory, 'execution-manifest.json'), 'utf8'),
  );
  assert.equal(
    manifest.source.revision,
    receipt.source.privateRevision.sha,
    'Suite source revision differs from artifact',
  );
  assert.equal(
    manifest.source.tree,
    receipt.source.privateRevision.tree,
    'Suite source tree differs from artifact',
  );
  assert.equal(receipt.source.validationOrigin, COMMITTED_PROJECTION);
  assert.equal(manifest.source.validationOrigin, receipt.source.validationOrigin);
  const canonical = validateSuiteManifest(manifest, expectedFiles);
  const fragments = [
    JSON.parse(readFileSync(path.join(directory, 'source-suite-result.json'), 'utf8')),
  ];
  if (canonical.suites.packageInterop.length) {
    const proof = JSON.parse(
      readFileSync(path.join(directory, 'package-interop-result.json'), 'utf8'),
    );
    assert.ok(subject, 'Candidate artifact subject required for package Interop');
    verifyPackageProof(proof, {
      manifest: canonical,
      workspace,
      subject,
      validation: 'ci-validated',
      reportsDirectory: path.join(directory, 'interop'),
    });
    fragments.push(proof);
  }
  return validateSuiteResults(canonical, fragments);
}
