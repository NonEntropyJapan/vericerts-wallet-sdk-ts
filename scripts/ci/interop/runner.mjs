import assert from 'node:assert/strict';
import {
  cpSync,
  existsSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { installArgs } from '../../packed-consumer/process.mjs';
import { COMMITTED_PROJECTION } from '../../packed-consumer/source-origin.mjs';
import { artifactSubject, candidateSubject, verifyEnvelope } from '../candidate.mjs';
import { execute } from '../environment.mjs';
import { requireStableSuite, validateSuiteResults } from '../suite-manifest.mjs';
import { verifyInteropCases } from './case-contract.mjs';
import { copyInteropHarness } from './harness.mjs';
import { verifyPackageProof } from './package-proof.mjs';
import { runInteropGroups } from './run-groups.mjs';

function artifactForSuite(directory, validation, source) {
  let artifact;
  if (validation === 'ci-validated') {
    assert.equal(source.validationOrigin, COMMITTED_PROJECTION);
    artifact = candidateSubject(directory);
    const envelope = JSON.parse(readFileSync(path.join(directory, 'validation.json'), 'utf8'));
    verifyEnvelope(directory, envelope, {
      repositoryId: Number(process.env.GITHUB_REPOSITORY_ID),
      runId: Number(process.env.GITHUB_RUN_ID),
      runAttempt: Number(process.env.GITHUB_RUN_ATTEMPT),
      workflowPath: process.env.SDK_PRODUCER_WORKFLOW,
      headSha: process.env.SDK_PRODUCER_HEAD_SHA,
    });
    assert.equal(envelope.sdkProjection.sha, source.revision);
    assert.equal(envelope.sdkProjection.tree, source.tree);
  } else {
    assert.equal(validation, 'local-suite', 'Unknown Interop validation tier');
    assert.ok(
      !existsSync(path.join(directory, 'validation.json')),
      'Local suite cannot use a candidate envelope',
    );
    artifact = artifactSubject(directory);
  }
  assert.equal(artifact.receipt.source.privateRevision.sha, source.revision);
  assert.equal(artifact.receipt.source.privateRevision.tree, source.tree);
  assert.equal(artifact.receipt.source.validationOrigin, source.validationOrigin);
  return artifact;
}

export function runPackageInterop({
  workspace,
  artifactDir,
  sourceSha,
  manifestFile,
  result,
  validation,
}) {
  workspace = realpathSync(workspace);
  const coverage = path.join(workspace, 'coverage');
  assert.equal(realpathSync(path.dirname(manifestFile)), coverage);
  assert.equal(path.basename(manifestFile), 'execution-manifest.json');
  assert.equal(realpathSync(path.dirname(result)), coverage);
  assert.equal(path.basename(result), 'package-interop-result.json');
  const manifest = JSON.parse(readFileSync(manifestFile, 'utf8'));
  const { source } = manifest;
  assert.equal(source.revision, sourceSha, 'Interop source does not match explicit revision');
  requireStableSuite(workspace, manifest);
  assert.ok(manifest.suites.packageInterop.length > 0, 'No package Interop tests to run');
  const artifact = artifactForSuite(artifactDir, validation, source);
  const consumer = realpathSync(mkdtempSync(path.join(tmpdir(), 'sdk-package-interop-')));
  try {
    const copied = copyInteropHarness(workspace, consumer);
    writeFileSync(path.join(consumer, 'package.json'), '{"private":true,"type":"module"}\n', {
      flag: 'wx',
    });
    execute('npm', [...installArgs, artifact.tarball], consumer, { stdio: 'inherit' });
    const sdk = path.join(consumer, 'node_modules/@vericerts/vericerts-wallet-sdk');
    assert.equal(realpathSync(sdk), sdk, 'Interop installed SDK is linked outside the consumer');
    assert.equal(existsSync(path.join(sdk, 'src')), false, 'Interop requires the packaged SDK');
    execute(
      'npm',
      ['ci', '--omit=dev', '--no-audit', '--no-fund'],
      path.join(consumer, 'test/interop/adapters/veramo'),
      {
        stdio: 'inherit',
      },
    );
    const bun = readFileSync(path.join(workspace, '.bun-version'), 'utf8').trim();
    const execution = runInteropGroups(consumer, bun);
    requireStableSuite(workspace, manifest);
    assert.deepEqual(
      artifactForSuite(artifactDir, validation, source).subject,
      artifact.subject,
      'Interop input artifact changed during execution',
    );
    const fragment = {
      version: 1,
      suite: 'packageInterop',
      validationTier: validation,
      source,
      artifact: {
        sha256: artifact.subject.tarballSha256,
        integrity: artifact.subject.integrity,
        receiptSha256: artifact.subject.receiptSha256,
      },
      harness: { ...copied, sdkSourceTree: source.tree },
      ...execution,
      caseParity: verifyInteropCases(execution.report.cases),
    };
    verifyPackageProof(fragment, {
      manifest,
      workspace,
      subject: artifact.subject,
      validation,
      reportsDirectory: path.join(consumer, 'coverage/interop'),
    });
    const sourceFragment = JSON.parse(
      readFileSync(path.join(coverage, 'source-suite-result.json'), 'utf8'),
    );
    const union = validateSuiteResults(manifest, [sourceFragment, fragment]);
    writeFileSync(result, `${JSON.stringify(fragment, null, 2)}\n`, { flag: 'wx' });
    writeFileSync(path.join(coverage, 'suite-union-result.json'), `${JSON.stringify(union)}\n`, {
      flag: 'wx',
    });
    console.log(`SDK source + package Interop complete (${union.files} test files)`);
    return union;
  } finally {
    const logs = path.join(consumer, 'coverage/interop');
    try {
      if (existsSync(logs))
        cpSync(logs, path.join(coverage, 'interop'), {
          recursive: true,
          force: false,
          errorOnExist: true,
        });
    } finally {
      rmSync(consumer, { recursive: true, force: true });
    }
  }
}
