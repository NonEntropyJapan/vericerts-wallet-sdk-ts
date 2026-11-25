import path from 'node:path';
import { isMainModule } from '../lib/is-main-module.mjs';
import { execute } from './environment.mjs';
import { validRevision } from './git-projection.mjs';
import { requirePreparedChromium } from './local/browser-preparation.mjs';

export function runArtifact(mode) {
  if (!['produce', 'consume', 'dry-run'].includes(mode))
    throw new Error('Unknown SDK artifact phase');
  const workspace = process.env.SDK_CI_WORKSPACE;
  const revision = process.env.SDK_CI_REVISION;
  const receipt = process.env.SDK_CI_RECEIPT;
  const tarball = process.env.SDK_CI_TARBALL;
  const directory = process.env.SDK_CI_ARTIFACT_DIR;
  if (
    ![workspace, receipt, tarball, directory].every(
      (value) => typeof value === 'string' && path.isAbsolute(value),
    ) ||
    !validRevision(revision)
  ) {
    throw new Error('Explicit isolated SDK artifact context is required');
  }
  if (mode === 'produce' && process.env.GITHUB_ACTIONS === 'true') {
    requirePreparedChromium(workspace);
  }
  const script = mode === 'dry-run' ? 'release.mjs' : 'run.mjs';
  const args =
    mode === 'produce'
      ? [
          `--artifact-dir=${directory}`,
          `--receipt=${receipt}`,
          `--source-sha=${revision}`,
          '--browser',
          '--bun',
        ]
      : [`--tarball=${tarball}`, `--receipt=${receipt}`, `--source-sha=${revision}`];
  execute(
    process.execPath,
    [path.join(workspace, 'scripts/packed-consumer', script), ...args],
    mode === 'produce' ? workspace : directory,
    { stdio: 'inherit' },
  );
}
if (isMainModule(import.meta.url)) {
  if (process.argv.length !== 3) throw new Error('usage: artifact.mjs produce|consume|dry-run');
  runArtifact(process.argv[2]);
}
