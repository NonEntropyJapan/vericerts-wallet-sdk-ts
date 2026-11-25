import assert from 'node:assert/strict';
import {
  cpSync,
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  renameSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { git } from '../../lib/repo-files.mjs';
import { COMMITTED_PROJECTION } from '../../packed-consumer/source-origin.mjs';
import { execute } from '../environment.mjs';
import { projectSdk } from '../git-projection.mjs';
import { currentSuiteManifest } from '../suite-manifest.mjs';
import { createLocalSnapshot, requireUnchangedInputs } from './local-snapshot.mjs';

const sourceRoot = fileURLToPath(new URL('../../../', import.meta.url));

function evidenceDirectory(sdk) {
  const root = path.join(realpathSync(sdk), 'coverage');
  mkdirSync(root, { recursive: true });
  assert.ok(
    lstatSync(root).isDirectory() && realpathSync(root) === root,
    'SDK coverage must be an owned directory',
  );
  return mkdtempSync(path.join(root, 'sdk-suite-'));
}

function copyRunEvidence(preparation, output) {
  const coverage = path.join(preparation.workspace, 'coverage');
  if (existsSync(coverage))
    cpSync(coverage, path.join(output, 'coverage'), { recursive: true, force: false });
}

function publishCoverage(sdk, output, names) {
  const dir = path.join(sdk, 'coverage');
  for (const name of names) {
    const source = path.join(output, 'coverage', name);
    const staging = path.join(output, name);
    writeFileSync(staging, readFileSync(source), { flag: 'wx' });
    renameSync(staging, path.join(dir, name));
  }
}

export function runSdkTests({ input, coverage, sdk = sourceRoot }) {
  assert.ok(['working-tree', 'committed'].includes(input), 'Choose an SDK test input');
  assert.match(process.versions.node, /^24\./, 'SDK full test tooling requires Node 24');
  const output = evidenceDirectory(sdk);
  const temporary = realpathSync(mkdtempSync(path.join(tmpdir(), 'sdk-local-suite-')));
  let preparation;
  let copied = false;
  try {
    preparation =
      input === 'working-tree'
        ? createLocalSnapshot(sdk, temporary)
        : { ...projectSdk(sdk, temporary), validationOrigin: COMMITTED_PROJECTION };
    const { workspace, validationOrigin, sdkProjectedSHA, sdkTree } = preparation;
    const pin = readFileSync(path.join(workspace, '.bun-version'), 'utf8').trim();
    assert.equal(
      execute('bun', ['--version'], workspace).trim(),
      pin,
      'Use the SDK pinned Bun version',
    );
    const run = (command, args) => execute(command, args, workspace, { stdio: 'inherit' });
    const node = (script, ...args) => run(process.execPath, [script, ...args]);
    run('bun', ['install', '--frozen-lockfile']);
    node('scripts/check-skipped-tests.mjs');
    const manifest = currentSuiteManifest(workspace, validationOrigin);
    assert.deepEqual(manifest.source, {
      revision: sdkProjectedSHA,
      tree: sdkTree,
      validationOrigin,
    });
    node(
      'scripts/ci/source-suite.mjs',
      `--validation-origin=${validationOrigin}`,
      ...(coverage ? ['--coverage'] : []),
    );
    if (coverage)
      node(
        'scripts/check-coverage.mjs',
        '--lcov=coverage/lcov.info',
        '--overall=80',
        '--crypto-prefix=src/internal/keymanager/',
        '--crypto-threshold=95',
        '--source-root=src',
        '--include-prefix=src/',
      );
    const artifacts = path.join(temporary, 'artifact');
    node(
      'scripts/ci/local-artifact.mjs',
      artifacts,
      path.join(artifacts, 'receipt.json'),
      sdkProjectedSHA,
      validationOrigin,
    );
    node(
      'scripts/ci/package-interop.mjs',
      `--workspace=${workspace}`,
      `--artifact-dir=${artifacts}`,
      `--source-sha=${sdkProjectedSHA}`,
      `--manifest=${path.join(workspace, 'coverage/execution-manifest.json')}`,
      `--result=${path.join(workspace, 'coverage/package-interop-result.json')}`,
      '--validation=local-suite',
    );
    copyRunEvidence(preparation, output);
    copied = true;
    if (input === 'working-tree') {
      cpSync(
        path.join(temporary, 'development-snapshot.json'),
        path.join(output, 'development-snapshot.json'),
      );
      requireUnchangedInputs(sdk, preparation.inputs);
    } else {
      assert.equal(
        git(sdk, ['rev-parse', 'HEAD']).trim(),
        preparation.producerRevision,
        'Committed SDK changed during validation',
      );
      assert.equal(
        git(sdk, ['status', '--porcelain', '--untracked-files=all', '--', '.']),
        '',
        'Committed SDK became dirty during validation',
      );
    }
    cpSync(path.join(artifacts, 'receipt.json'), path.join(output, 'receipt.json'));
    publishCoverage(sdk, output, ['junit.xml', ...(coverage ? ['lcov.info'] : [])]);
    writeFileSync(
      path.join(output, 'status.json'),
      `${JSON.stringify({ complete: true, currentInputsMatch: true, validationTier: 'local-suite', source: manifest.source })}\n`,
      { flag: 'wx' },
    );
    console.log(`Local SDK source + package Interop validation: ${output}`);
    return output;
  } catch (error) {
    if (preparation && !copied) copyRunEvidence(preparation, output);
    writeFileSync(
      path.join(output, 'status.json'),
      `${JSON.stringify({ complete: false, error: error.message })}\n`,
      { flag: 'wx' },
    );
    console.error(`SDK validation failed. This run's evidence is in ${output}.`);
    throw error;
  } finally {
    rmSync(temporary, { recursive: true, force: true });
  }
}
