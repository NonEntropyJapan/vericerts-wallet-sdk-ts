import { afterAll, describe, expect, test } from 'bun:test';
import { copyFileSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import {
  candidateSubject,
  createEnvelope,
  releaseCandidateForPush,
  SDK_JOBS,
  verifyEnvelope,
  verifyNeeds,
} from '../ci/candidate.mjs';
import { verifySuiteProofs } from '../ci/interop/candidate-proof.mjs';
import { createSuiteManifest } from '../ci/suite-manifest.mjs';
import { fixture as artifactFixture } from '../packed-consumer/artifact-fixtures.mjs';

const artifact = artifactFixture();
afterAll(() => rmSync(artifact.root, { recursive: true, force: true }));
const directory = path.join(artifact.root, 'candidate');
mkdirSync(directory);
copyFileSync(artifact.tarball, path.join(directory, artifact.receipt.artifact.filename));
copyFileSync(artifact.receiptPath, path.join(directory, 'receipt.json'));
const producer = {
  repositoryId: 1,
  workflowPath: '.github/workflows/ci-sdk.yml',
  runId: 2,
  runAttempt: 3,
  headSha: 'e'.repeat(40),
};
const projection = {
  producerRevision: producer.headSha,
  sdkProjectedSHA: artifact.receipt.source.privateRevision.sha,
  sdkTree: artifact.receipt.source.privateRevision.tree,
};
const save = (file: string, value: unknown) =>
  writeFileSync(path.join(directory, file), JSON.stringify(value));
describe('SDK private validation candidate', () => {
  test('binds the planned Git tag to the SDK push and validated tarball', () => {
    const split = { ...producer, workflowPath: '.github/workflows/ci.yml' };
    const push = {
      GITHUB_EVENT_NAME: 'push',
      GITHUB_REPOSITORY: 'example/sdk',
      GITHUB_SHA: split.headSha,
    };
    const pkg = artifact.receipt.artifact;
    const report = releaseCandidateForPush(pkg, split, push);
    expect(report?.targetSha).toBe(split.headSha);
    expect(report?.tarballSha256).toBe(pkg.sha256);
    expect(releaseCandidateForPush(pkg, producer, push)).toBeNull();
    const pr = { ...push, GITHUB_EVENT_NAME: 'pull_request' };
    expect(releaseCandidateForPush(pkg, split, pr)).toBeNull();
    const wrongHead = { ...push, GITHUB_SHA: projection.sdkProjectedSHA };
    expect(() => releaseCandidateForPush(pkg, split, wrongHead)).toThrow('pushed commit');
  });
  test('requires the exact SDK five jobs and no monorepo-only prerequisite', () => {
    const needs = Object.fromEntries(SDK_JOBS.map((name) => [name, { result: 'success' }]));
    expect(() => verifyNeeds(needs)).not.toThrow();
    for (const name of SDK_JOBS) {
      expect(() => verifyNeeds({ ...needs, [name]: { result: 'skipped' } })).toThrow();
      const missing = { ...needs };
      delete missing[name];
      expect(() => verifyNeeds(missing)).toThrow();
    }
    expect(() => verifyNeeds({ ...needs, 'extension-build': { result: 'success' } })).toThrow();
  });
  test('binds both distinct revisions, all runtime checks and same tarball/receipt bytes', () => {
    const envelope = createEnvelope(directory, projection, producer);
    expect(envelope.producer.headSha).not.toBe(envelope.sdkProjection.sha);
    expect(envelope.publicRevision).toBeNull();
    save('validation.json', envelope);
    expect(() => verifyEnvelope(directory, envelope, producer)).not.toThrow();
    expect(() =>
      createEnvelope(directory, { ...projection, producerRevision: 'f'.repeat(40) }, producer),
    ).toThrow();
    expect(() =>
      createEnvelope(directory, { ...projection, sdkProjectedSHA: 'f'.repeat(40) }, producer),
    ).toThrow();
    for (const change of [
      { context: 'public' },
      { publicRevision: { sha: producer.headSha } },
      { producer: { ...producer, runAttempt: 4 } },
      { subject: { ...envelope.subject, receiptSha256: 'f'.repeat(64) } },
    ])
      expect(() => verifyEnvelope(directory, { ...envelope, ...change }, producer)).toThrow();
    save('receipt.json', { ...artifact.receipt, checks: { ...artifact.receipt.checks, node: [] } });
    expect(() => candidateSubject(directory)).toThrow();
    copyFileSync(artifact.receiptPath, path.join(directory, 'receipt.json'));
    writeFileSync(path.join(directory, artifact.receipt.artifact.filename), 'changed');
    expect(() => candidateSubject(directory)).toThrow();
    copyFileSync(artifact.tarball, path.join(directory, artifact.receipt.artifact.filename));
    save('unexpected.json', {});
    expect(() => candidateSubject(directory)).toThrow();
    rmSync(path.join(directory, 'unexpected.json'));
  });
  test('requires a complete same-source source/package union before validation', () => {
    const subject = candidateSubject(directory).subject;
    const source = {
      revision: projection.sdkProjectedSHA,
      tree: projection.sdkTree,
      validationOrigin: 'committed-projection',
    };
    const manifest = createSuiteManifest(
      ['src/core.test.ts', ...Array.from({ length: 29 }, (_, i) => `test/interop/${i}.test.mjs`)],
      source,
    );
    const result = (suite: string, files: string[]) => ({
      suite,
      source,
      report: {
        files,
        declaredTests: files.length,
        cases: files.map((file) => ({ file, name: 'runs', status: 'passed' })),
      },
    });
    save('execution-manifest.json', manifest);
    save('source-suite-result.json', result('source', manifest.suites.source));
    expect(() =>
      verifySuiteProofs(directory, artifact.receipt, { expectedFiles: manifest.files }),
    ).toThrow();
    save('package-interop-result.json', result('packageInterop', manifest.suites.packageInterop));
    const verify = () =>
      verifySuiteProofs(directory, artifact.receipt, { expectedFiles: manifest.files, subject });
    expect(verify).toThrow('Unsupported package Interop proof');
    expect(() =>
      verifySuiteProofs(directory, artifact.receipt, {
        expectedFiles: [...manifest.files, 'src/omitted.test.ts'],
      }),
    ).toThrow('tracked SDK test files');
    save(
      'package-interop-result.json',
      result('packageInterop', manifest.suites.packageInterop.slice(1)),
    );
    expect(verify).toThrow('Unsupported package Interop proof');
    save('package-interop-result.json', {
      ...result('packageInterop', manifest.suites.packageInterop),
      version: 1,
      validationTier: 'ci-validated',
      source: { ...source, revision: producer.headSha },
    });
    expect(verify).toThrow('source identity differs');
  });
});
