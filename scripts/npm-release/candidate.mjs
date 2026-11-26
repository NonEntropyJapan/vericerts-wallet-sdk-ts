import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { appendFileSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { verifyEnvelope } from '../ci/candidate.mjs';
import { isMainModule } from '../lib/is-main-module.mjs';
import { inspectArtifact } from '../packed-consumer/archive.mjs';
import { assertReceiptArtifact, readReceipt } from '../packed-consumer/receipt.mjs';
import { plannedReleaseTag } from '../packed-consumer/release.mjs';

const workflowPath = '.github/workflows/ci.yml';
const packageName = 'vericerts-wallet-sdk';
const json = (file) => JSON.parse(readFileSync(file, 'utf8'));

function positiveId(value) {
  assert.match(String(value), /^[1-9]\d*$/);
  assert.ok(Number.isSafeInteger(Number(value)));
  return Number(value);
}

export function releaseProducer(
  artifact,
  run,
  workflow,
  { artifactId, repositoryId, repository, sha },
) {
  assert.match(sha, /^[0-9a-f]{40}$/);
  assert.equal(artifact.id, positiveId(artifactId));
  assert.equal(artifact.expired, false);
  assert.equal(run.id, positiveId(artifact.workflow_run.id));
  assert.equal(workflow.path, workflowPath);
  assert.equal(workflow.state, 'active');
  assert.equal(run.workflow_id, positiveId(workflow.id));
  assert.equal(run.path, workflowPath);
  assert.equal(run.event, 'push');
  assert.equal(run.status, 'completed');
  assert.equal(run.conclusion, 'success');
  for (const repo of [run.repository, run.head_repository]) {
    assert.equal(repo.id, repositoryId);
    assert.equal(repo.full_name, repository);
    assert.equal(repo.private, false);
  }
  assert.equal(artifact.workflow_run.repository_id, repositoryId);
  assert.equal(artifact.workflow_run.head_repository_id, repositoryId);
  for (const source of [run, artifact.workflow_run]) {
    assert.equal(source.head_branch, 'main');
    assert.equal(source.head_sha, sha);
  }
  const runAttempt = positiveId(run.run_attempt);
  assert.equal(artifact.name, `sdk-validated-candidate-${sha}-${runAttempt}`);
  return { repositoryId, workflowPath, runId: run.id, runAttempt, headSha: sha };
}

export function releaseSubject(directory, producer, { sha256, tree, manifest, repository }) {
  assert.match(sha256, /^[0-9a-f]{64}$/);
  const envelope = json(join(directory, 'validation.json'));
  verifyEnvelope(directory, envelope, producer);
  assert.equal(envelope.sdkProjection.tree, tree, 'Candidate tree differs from signing source');
  assert.equal(envelope.subject.tarballSha256, sha256, 'Candidate differs from reviewed tarball');
  const receipt = readReceipt(join(directory, 'receipt.json'));
  const { filename } = receipt.artifact;
  const { pkg, artifact } = inspectArtifact(join(directory, filename));
  assertReceiptArtifact(receipt, artifact, envelope.sdkProjection.sha);
  assert.equal(pkg.name, packageName);
  assert.equal(pkg.name, manifest.name);
  assert.equal(pkg.version, manifest.version);
  plannedReleaseTag(pkg.version);
  assert.equal(filename, `${pkg.name}-${pkg.version}.tgz`);
  assert.equal(pkg.repository.url, `git+https://github.com/${repository}.git`);
  assert.deepEqual(pkg.publishConfig, { access: 'public' });
  return {
    filename,
    purl: `pkg:npm/${pkg.name}@${pkg.version}`,
    sha512: Buffer.from(artifact.integrity.slice('sha512-'.length), 'base64').toString('hex'),
  };
}

if (isMainModule(import.meta.url)) {
  const env = process.env;
  const producerFile = join(env.RUNNER_TEMP, 'release-producer.json');
  const repository = env.GITHUB_REPOSITORY;
  const sha = env.GITHUB_SHA;
  const output = (name, value) => appendFileSync(env.GITHUB_OUTPUT, `${name}=${value}\n`);
  if (process.argv[2] === 'producer') {
    assert.equal(env.GITHUB_WORKFLOW_SHA, sha, 'Signing workflow differs from release source');
    const api = (path) =>
      JSON.parse(execFileSync('gh', ['api', `repos/${repository}/actions/${path}`]));
    const artifactId = positiveId(env.CANDIDATE_ID);
    const artifact = api(`artifacts/${artifactId}`);
    const run = api(`runs/${positiveId(artifact.workflow_run.id)}`);
    const producer = releaseProducer(artifact, run, api('workflows/ci.yml'), {
      artifactId,
      repository,
      repositoryId: positiveId(env.GITHUB_REPOSITORY_ID),
      sha,
    });
    writeFileSync(producerFile, JSON.stringify(producer), { flag: 'wx' });
    output('run', producer.runId);
  } else {
    assert.equal(process.argv[2], 'subject');
    const subject = releaseSubject(join(env.RUNNER_TEMP, 'candidate'), json(producerFile), {
      sha256: env.REVIEWED_SHA256,
      tree: execFileSync('git', ['rev-parse', `${sha}^{tree}`], { encoding: 'utf8' }).trim(),
      manifest: json('package.json'),
      repository,
    });
    for (const [name, value] of Object.entries(subject)) output(name, value);
  }
}
