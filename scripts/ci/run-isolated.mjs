import path from 'node:path';
import { isMainModule } from '../lib/is-main-module.mjs';
import { execute } from './environment.mjs';
import { exportWorkspace, prepareWorkspace } from './prepare-workspace.mjs';

export function runIsolated(profile, base) {
  if (process.env.GITHUB_EVENT_NAME === 'pull_request' && !base)
    throw new Error('PR SDK base revision is required');
  const result = prepareWorkspace({ base });
  exportWorkspace(result);
  execute('bun', ['install', '--frozen-lockfile'], result.workspace, { stdio: 'inherit' });
  execute(
    process.execPath,
    [
      path.join(result.workspace, 'scripts/ci/run.mjs'),
      `--profile=${profile}`,
      ...(result.sdkProjectedBase ? [`--base=${result.sdkProjectedBase}`] : []),
    ],
    result.workspace,
    { stdio: 'inherit' },
  );
  return result;
}
if (isMainModule(import.meta.url)) {
  const args = process.argv.slice(2);
  if (args.length !== 1 || !args[0].startsWith('--profile='))
    throw new Error('usage: --profile=<static|unit|conformance|node>');
  runIsolated(args[0].slice(10), process.env.SDK_BASE_REVISION || undefined);
}
