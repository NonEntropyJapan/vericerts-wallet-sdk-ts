import assert from 'node:assert/strict';
import {
  appendFileSync,
  copyFileSync,
  lstatSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  realpathSync,
  writeFileSync,
} from 'node:fs';
import path from 'node:path';
import { isMainModule } from '../../lib/is-main-module.mjs';
import { git } from '../../lib/repo-files.mjs';
import { inside } from '../../packed-consumer/containment.mjs';
import { COMMITTED_PROJECTION } from '../../packed-consumer/source-origin.mjs';
import { candidateSubject, sha256 } from '../candidate.mjs';
import { validRevision } from '../git-projection.mjs';
import { copyInteropHarness, inventoryInteropHarness } from './harness.mjs';

const ARTIFACT = 'artifact';
const RECEIPT = 'receipt.json';
const BINDING = 'live-binding.json';

function absolute(input, label) {
  assert.ok(
    input && path.isAbsolute(input) && !/[\r\n]/.test(input),
    `${label} must be an absolute path`,
  );
  return path.resolve(input);
}

function readJson(file) {
  assert.ok(lstatSync(file).isFile(), `Expected a regular file: ${file}`);
  return JSON.parse(readFileSync(file, 'utf8'));
}

function checkDirectory(directory, names) {
  assert.ok(lstatSync(directory).isDirectory(), `Expected a real directory: ${directory}`);
  assert.deepEqual(
    readdirSync(directory).sort(),
    [...names].sort(),
    `Unexpected files in ${directory}`,
  );
}

function projectedInput(env) {
  const workspace = absolute(env.SDK_CI_WORKSPACE, 'SDK workspace');
  const producer = env.GITHUB_SHA;
  const projection = readJson(absolute(env.SDK_CI_PROJECTION, 'projection'));
  assert.ok(validRevision(producer), 'Exact producer SHA is required');
  assert.equal(projection.context, 'private-validation');
  assert.equal(projection.producerRevision, producer, 'Producer SHA differs from SDK projection');
  assert.equal(
    projection.sdkProjectedSHA,
    env.SDK_CI_REVISION,
    'Projected SHA differs from SDK workspace',
  );
  assert.equal(git(workspace, ['rev-parse', 'HEAD']).trim(), projection.sdkProjectedSHA);
  assert.equal(git(workspace, ['rev-parse', 'HEAD^{tree}']).trim(), projection.sdkTree);
  assert.equal(
    git(workspace, ['status', '--porcelain', '--untracked-files=all', '--', '.']),
    '',
    'Interop projected SDK source is not clean',
  );
  return { workspace, producer, projection };
}

function verifiedArtifact(directory, { workspace, producer, projection }) {
  assert.ok(lstatSync(directory).isDirectory(), 'Interop artifact must be a real directory');
  const names = readdirSync(directory);
  assert.equal(names.length, 2, 'Interop artifact must contain only the tarball and receipt');
  assert.ok(names.includes(RECEIPT), 'Missing Interop artifact receipt');
  for (const name of names) {
    assert.ok(
      lstatSync(path.join(directory, name)).isFile(),
      'Interop artifact files must be regular',
    );
  }
  const { receipt, subject } = candidateSubject(directory);
  const { filename } = receipt.artifact;
  const { sha, tree, lockSha256 } = receipt.source.privateRevision;
  assert.equal(sha, projection.sdkProjectedSHA, 'Tarball receipt projected SHA differs');
  assert.equal(tree, projection.sdkTree, 'Tarball receipt projected tree differs');
  assert.equal(
    lockSha256,
    sha256(readFileSync(path.join(workspace, 'bun.lock'))),
    'SDK lock differs from tarball receipt',
  );
  return {
    filename,
    binding: {
      context: 'private-validation',
      validationTier: 'runtime-receipt',
      validationOrigin: COMMITTED_PROJECTION,
      producerHeadSha: producer,
      sdkProjectedSHA: sha,
      sdkTree: tree,
      artifactSha256: subject.tarballSha256,
      receiptSha256: subject.receiptSha256,
      integrity: subject.integrity,
      harnessManifestSha256: inventoryInteropHarness(workspace).manifestSha256,
    },
  };
}

function copyArtifact(directory, target, filename) {
  mkdirSync(target);
  for (const name of [filename, RECEIPT])
    copyFileSync(path.join(directory, name), path.join(target, name));
}

function mkdirOutsideWorkspace(workspace, output) {
  const target = path.join(realpathSync(path.dirname(output)), path.basename(output));
  assert.ok(!inside(realpathSync(workspace), target), 'Interop output must be outside SDK source');
  mkdirSync(target);
}

function outputFields(binding) {
  return {
    sdk_projected_sha: binding.sdkProjectedSHA,
    sdk_tree: binding.sdkTree,
    producer_head_sha: binding.producerHeadSha,
    artifact_sha256: binding.artifactSha256,
    receipt_sha256: binding.receiptSha256,
  };
}

export function finalizeLiveArtifact(bundlePath, env = process.env) {
  const bundle = absolute(bundlePath, 'Interop bundle');
  const input = projectedInput(env);
  const artifact = absolute(env.SDK_CI_ARTIFACT_DIR, 'Interop artifact');
  const { filename, binding } = verifiedArtifact(artifact, input);
  mkdirOutsideWorkspace(input.workspace, bundle);
  const bundleArtifact = path.join(bundle, ARTIFACT);
  copyArtifact(artifact, bundleArtifact, filename);
  assert.deepEqual(
    verifiedArtifact(bundleArtifact, input).binding,
    binding,
    'Copied bundle differs from producer artifact',
  );
  writeFileSync(path.join(bundle, BINDING), `${JSON.stringify(binding, null, 2)}\n`, {
    flag: 'wx',
  });
  if (env.GITHUB_OUTPUT) {
    const outputs = Object.entries(outputFields(binding)).map(
      ([key, value]) => `${key}=${value}\n`,
    );
    appendFileSync(env.GITHUB_OUTPUT, outputs.join(''));
  }
}

export function materializeLiveContext(bundlePath, contextPath, env = process.env) {
  const bundle = absolute(bundlePath, 'Interop bundle');
  const context = absolute(contextPath, 'Interop context');
  const input = projectedInput(env);
  checkDirectory(bundle, [ARTIFACT, BINDING]);
  const artifact = path.join(bundle, ARTIFACT);
  const { filename, binding } = verifiedArtifact(artifact, input);
  assert.deepEqual(readJson(path.join(bundle, BINDING)), binding, 'Interop bundle binding differs');
  if (env.GITHUB_ACTIONS === 'true') {
    for (const [key, value] of Object.entries(outputFields(binding))) {
      assert.equal(
        env[`INTEROP_EXPECTED_${key.toUpperCase()}`],
        value,
        `Interop provider output differs: ${key}`,
      );
    }
  }

  mkdirOutsideWorkspace(input.workspace, context);
  const copiedHarness = copyInteropHarness(input.workspace, context);
  assert.equal(
    copiedHarness.manifestSha256,
    binding.harnessManifestSha256,
    'Copied Interop harness differs from producer source',
  );
  const contextArtifact = path.join(context, ARTIFACT);
  copyArtifact(artifact, contextArtifact, filename);
  assert.deepEqual(
    verifiedArtifact(contextArtifact, projectedInput(env)).binding,
    binding,
    'Copied context differs from producer artifact',
  );
  writeFileSync(
    path.join(context, 'package.json'),
    `${JSON.stringify({ name: 'interop-artifact-consumer', private: true, type: 'module' }, null, 2)}\n`,
    { flag: 'wx' },
  );
  if (env.GITHUB_ENV) appendFileSync(env.GITHUB_ENV, `INTEROP_CONTEXT=${context}\n`);
}

if (isMainModule(import.meta.url)) {
  const [command, bundle, context, extra] = process.argv.slice(2);
  if (command === 'finalize' && !context) finalizeLiveArtifact(bundle);
  else if (command === 'materialize' && context && !extra) materializeLiveContext(bundle, context);
  else throw new Error('usage: live.mjs finalize <bundle> | materialize <bundle> <context>');
}
