import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { lstatSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { isMainModule } from '../lib/is-main-module.mjs';
import { readReceipt, requireReleaseChecks } from '../packed-consumer/receipt.mjs';
import { plannedReleaseCandidate } from '../packed-consumer/release.mjs';

export const SDK_JOBS = ['ci-bun', 'ci-bun-static', 'ci-bun-build', 'ci-node-20-lts', 'ci-node-22'];
export const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');
const positiveInteger = (value) => Number.isSafeInteger(Number(value)) && Number(value) > 0;

export function verifyNeeds(needs) {
  assert.deepEqual(
    Object.keys(needs).sort(),
    [...SDK_JOBS].sort(),
    'SDK candidate dependencies changed',
  );
  for (const name of SDK_JOBS)
    assert.equal(needs[name].result, 'success', `SDK job ${name} did not succeed`);
}

export function artifactSubject(directory) {
  const receiptFile = path.join(directory, 'receipt.json');
  const receipt = readReceipt(receiptFile);
  const filename = receipt.artifact.filename;
  assert.ok(
    typeof filename === 'string' && /^[a-zA-Z0-9._-]+\.tgz$/.test(filename),
    'Unsafe candidate tarball filename',
  );
  const files = readdirSync(directory).sort();
  assert.deepEqual(
    files.filter((name) => name !== 'validation.json'),
    [filename, 'receipt.json'].sort(),
    'Candidate contains missing/extra files',
  );
  assert.ok(
    files.every((name) => lstatSync(path.join(directory, name)).isFile()),
    'Candidate files must be regular files',
  );
  const bytes = readFileSync(path.join(directory, filename));
  assert.equal(sha256(bytes), receipt.artifact.sha256, 'Candidate tarball changed');
  assert.equal(
    `sha512-${createHash('sha512').update(bytes).digest('base64')}`,
    receipt.artifact.integrity,
    'Candidate SRI changed',
  );
  return {
    receipt,
    tarball: path.join(directory, filename),
    subject: {
      tarballSha256: sha256(bytes),
      receiptSha256: sha256(readFileSync(receiptFile)),
      integrity: receipt.artifact.integrity,
    },
  };
}

export function candidateSubject(directory) {
  const artifact = artifactSubject(directory);
  requireReleaseChecks(artifact.receipt);
  return artifact;
}

export function createEnvelope(directory, projection, producer) {
  for (const field of ['repositoryId', 'runId', 'runAttempt'])
    assert.ok(positiveInteger(producer[field]), `Invalid producer ${field}`);
  assert.match(producer.headSha, /^[a-f0-9]{40}$/);
  assert.ok(
    ['.github/workflows/ci-sdk.yml', '.github/workflows/ci.yml'].includes(producer.workflowPath),
  );
  const { receipt, subject } = candidateSubject(directory);
  assert.equal(
    projection.producerRevision,
    producer.headSha,
    'Producer SHA differs from private SDK projection',
  );
  assert.equal(
    receipt.source.privateRevision.sha,
    projection.sdkProjectedSHA,
    'SDK projected SHA differs',
  );
  assert.equal(
    receipt.source.privateRevision.tree,
    projection.sdkTree,
    'SDK projected tree differs',
  );
  return {
    schemaVersion: 1,
    context: 'private-validation',
    producer,
    sdkProjection: { sha: projection.sdkProjectedSHA, tree: projection.sdkTree },
    subject,
    publicRevision: null,
  };
}

export function verifyEnvelope(directory, envelope, producer) {
  assert.equal(envelope.schemaVersion, 1);
  assert.equal(envelope.context, 'private-validation');
  assert.equal(envelope.publicRevision, null);
  assert.deepEqual(envelope.producer, producer, 'Candidate producer identity changed');
  const { receipt, subject } = candidateSubject(directory);
  assert.deepEqual(envelope.subject, subject, 'Candidate artifact/receipt changed');
  assert.equal(envelope.sdkProjection.sha, receipt.source.privateRevision.sha);
  assert.equal(envelope.sdkProjection.tree, receipt.source.privateRevision.tree);
}

export function releaseCandidateForPush(artifact, producer, env) {
  if (producer.workflowPath !== '.github/workflows/ci.yml' || env.GITHUB_EVENT_NAME !== 'push') {
    return null;
  }
  assert.equal(producer.headSha, env.GITHUB_SHA, 'SDK tag target differs from the pushed commit');
  return plannedReleaseCandidate(artifact, env.GITHUB_REPOSITORY, producer.headSha);
}

if (isMainModule(import.meta.url)) {
  const [mode] = process.argv.slice(2);
  if (!['create', 'aggregate'].includes(mode) || process.argv.length !== 3)
    throw new Error('usage: candidate.mjs create|aggregate');
  const directory = process.env.SDK_CI_ARTIFACT_DIR;
  if (!directory) throw new Error('Candidate artifact directory is required');
  const producer = {
    repositoryId: Number(process.env.GITHUB_REPOSITORY_ID),
    workflowPath: process.env.SDK_PRODUCER_WORKFLOW,
    runId: Number(process.env.GITHUB_RUN_ID),
    runAttempt: Number(process.env.GITHUB_RUN_ATTEMPT),
    headSha: process.env.SDK_PRODUCER_HEAD_SHA,
  };
  const target = path.join(directory, 'validation.json');
  if (mode === 'create') {
    const projection = JSON.parse(readFileSync(process.env.SDK_CI_PROJECTION, 'utf8'));
    writeFileSync(
      target,
      `${JSON.stringify(createEnvelope(directory, projection, producer), null, 2)}\n`,
      { flag: 'wx' },
    );
  } else {
    verifyNeeds(JSON.parse(process.env.SDK_JOB_RESULTS));
    verifyEnvelope(directory, JSON.parse(readFileSync(target, 'utf8')), producer);
    const { receipt, subject } = candidateSubject(directory);
    const { verifySuiteProofs } = await import('./interop/candidate-proof.mjs');
    verifySuiteProofs(process.env.SDK_SUITE_RESULTS_DIR, receipt, { subject });
    const releaseCandidate = releaseCandidateForPush(receipt.artifact, producer, process.env);
    if (releaseCandidate) console.log(JSON.stringify(releaseCandidate));
  }
  console.log(
    'SDK candidate private validation envelope verified; no public source provenance established',
  );
}
