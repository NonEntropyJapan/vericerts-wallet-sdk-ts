import { afterAll, expect, test } from 'bun:test';
import { createHash } from 'node:crypto';
import { copyFileSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { createEnvelope } from '../ci/candidate.mjs';
import { inspectArtifact } from '../packed-consumer/archive.mjs';
import { fixture } from '../packed-consumer/artifact-fixtures.mjs';
import { releaseProducer, releaseSubject } from './candidate.mjs';

const sha = 'a'.repeat(40);
const repository = 'example/sdk';
const repo = { id: 7, full_name: repository, private: false };
const workflow = { id: 11, path: '.github/workflows/ci.yml', state: 'active' };
const run = {
  id: 13,
  run_attempt: 2,
  workflow_id: workflow.id,
  path: workflow.path,
  event: 'push',
  status: 'completed',
  conclusion: 'success',
  head_branch: 'main',
  head_sha: sha,
  repository: repo,
  head_repository: repo,
};
const candidate = {
  id: 17,
  expired: false,
  name: `sdk-validated-candidate-${sha}-2`,
  workflow_run: {
    id: run.id,
    repository_id: repo.id,
    head_repository_id: repo.id,
    head_branch: 'main',
    head_sha: sha,
  },
};
const context = { artifactId: candidate.id, repositoryId: repo.id, repository, sha };
const producer = releaseProducer(candidate, run, workflow, context);

test.each([
  ['pull request', { event: 'pull_request' }],
  ['fork', { head_repository: { ...repo, id: 8 } }],
  ['private repository', { repository: { ...repo, private: true } }],
  ['failed CI', { conclusion: 'failure' }],
  ['other workflow', { workflow_id: 21 }],
  ['previous attempt', { run_attempt: 3 }],
  ['different source', { head_sha: 'c'.repeat(40) }],
  ['different branch', { head_branch: 'develop' }],
])('rejects %s', (_name, change) => {
  expect(() => releaseProducer(candidate, { ...run, ...change }, workflow, context)).toThrow();
});

test.each([
  ['expired candidate', { expired: true }],
  ['intermediate artifact', { name: `sdk-package-validation-${sha}-2` }],
  ['different artifact ID', { id: 18 }],
  ['unrelated run', { workflow_run: { ...candidate.workflow_run, id: 23 } }],
])('rejects %s', (_name, change) => {
  expect(() => releaseProducer({ ...candidate, ...change }, run, workflow, context)).toThrow();
});

const sample = fixture();
afterAll(() => rmSync(sample.root, { recursive: true, force: true }));
const manifestPath = join(sample.packageRoot, 'package.json');
const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
manifest.repository = { type: 'git', url: `git+https://github.com/${repository}.git` };
manifest.publishConfig = { access: 'public' };
writeFileSync(manifestPath, JSON.stringify(manifest));
sample.repack();
const directory = join(sample.root, 'candidate');
mkdirSync(directory);
const { artifact } = inspectArtifact(sample.tarball);
const filename = `${manifest.name}-${manifest.version}.tgz`;
copyFileSync(sample.tarball, join(directory, filename));
sample.receipt.artifact = { ...artifact, filename };
writeFileSync(join(directory, 'receipt.json'), JSON.stringify(sample.receipt));
const revision = sample.receipt.source.privateRevision;
const envelope = createEnvelope(
  directory,
  {
    producerRevision: sha,
    sdkProjectedSHA: revision.sha,
    sdkTree: revision.tree,
  },
  producer,
);
writeFileSync(join(directory, 'validation.json'), JSON.stringify(envelope));
const options = { sha256: artifact.sha256, tree: revision.tree, manifest, repository };

test('uses the npm package URL and SHA-512 of the tested bytes as its single subject', () => {
  expect(releaseSubject(directory, producer, options)).toEqual({
    filename,
    purl: `pkg:npm/${manifest.name}@${manifest.version}`,
    sha512: createHash('sha512').update(readFileSync(sample.tarball)).digest('hex'),
  });
});

test.each([
  ['consumer digest', { sha256: 'd'.repeat(64) }],
  ['signing tree', { tree: 'e'.repeat(40) }],
  ['package version', { manifest: { ...manifest, version: '1.2.3' } }],
  ['package repository', { repository: 'example/other' }],
])('rejects mismatched %s', (_name, change) => {
  expect(() => releaseSubject(directory, producer, { ...options, ...change })).toThrow();
});
