import path from 'node:path';
import { isMainModule } from '../lib/is-main-module.mjs';
import { git } from '../lib/repo-files.mjs';
import { execute } from './environment.mjs';
import { validRevision } from './git-projection.mjs';
import { prepareChromium } from './local/browser-preparation.mjs';

export function runPrepared(mode) {
  if (!['install', 'browser', 'conformance'].includes(mode))
    throw new Error('Unknown prepared SDK phase');
  const workspace = process.env.SDK_CI_WORKSPACE;
  const revision = process.env.SDK_CI_REVISION;
  if (
    !workspace ||
    !path.isAbsolute(workspace) ||
    !validRevision(revision) ||
    git(workspace, ['rev-parse', 'HEAD']).trim() !== revision
  ) {
    throw new Error('Exact prepared SDK workspace/revision is required');
  }
  if (mode === 'install')
    execute('bun', ['install', '--frozen-lockfile'], workspace, { stdio: 'inherit' });
  else if (mode === 'browser') console.log(prepareChromium(workspace));
  else
    execute(
      process.execPath,
      [path.join(workspace, 'scripts/ci/run.mjs'), '--profile=conformance'],
      workspace,
      { stdio: 'inherit' },
    );
}
if (isMainModule(import.meta.url)) {
  if (process.argv.length !== 3) throw new Error('usage: prepared.mjs install|browser|conformance');
  runPrepared(process.argv[2]);
}
