import assert from 'node:assert/strict';
import { mkdtempSync, realpathSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { git } from '../../lib/repo-files.mjs';
import { execute } from '../environment.mjs';
import { createLocalSnapshot, requireUnchangedInputs } from './local-snapshot.mjs';

export function packDirtySdk(sdk, options) {
  if (!git(sdk, ['status', '--porcelain', '--untracked-files=all', '--', '.'])) return false;
  assert.ok(!options['source-sha'], 'Explicit source SHA requires clean SDK inputs');
  const temporary = realpathSync(mkdtempSync(path.join(tmpdir(), 'sdk-smoke-source-')));
  try {
    const { workspace, inputs, sdkProjectedSHA } = createLocalSnapshot(sdk, temporary);
    const executeInSnapshot = (command, args) =>
      execute(command, args, workspace, { stdio: 'inherit' });
    executeInSnapshot('bun', ['install', '--frozen-lockfile']);
    executeInSnapshot(process.execPath, [
      path.join(workspace, 'scripts/packed-consumer/run.mjs'),
      '--development-snapshot',
      `--source-sha=${sdkProjectedSHA}`,
      ...['artifact-dir', 'receipt']
        .filter((key) => options[key])
        .map((key) => `--${key}=${options[key]}`),
      ...(options.browser ? ['--browser'] : []),
      ...(options.bun ? ['--bun'] : []),
    ]);
    requireUnchangedInputs(sdk, inputs);
    return true;
  } finally {
    rmSync(temporary, { recursive: true, force: true });
  }
}
