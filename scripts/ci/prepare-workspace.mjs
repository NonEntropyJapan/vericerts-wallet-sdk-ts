import { appendFileSync, mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { isMainModule } from '../lib/is-main-module.mjs';
import { projectSdk } from './git-projection.mjs';

export function prepareWorkspace({ output, base, head } = {}) {
  return projectSdk(
    fileURLToPath(new URL('../../', import.meta.url)),
    output ?? mkdtempSync(path.join(tmpdir(), 'sdk-only-validation-')),
    { base, head },
  );
}

export function exportWorkspace(result) {
  const pkg = JSON.parse(readFileSync(path.join(result.workspace, 'package.json'), 'utf8'));
  if (
    !/^[@a-z0-9._/-]+$/.test(pkg.name) ||
    !/^\d+\.\d+\.\d+(?:[-+][a-zA-Z0-9.-]+)?$/.test(pkg.version)
  )
    throw new Error('Invalid SDK package identity');
  const artifacts = path.join(path.dirname(result.workspace), 'artifact');
  const filename = `${pkg.name.replace(/^@/, '').replaceAll('/', '-')}-${pkg.version}.tgz`;
  if (process.env.GITHUB_ENV)
    appendFileSync(
      process.env.GITHUB_ENV,
      `SDK_CI_WORKSPACE=${result.workspace}\nSDK_CI_REVISION=${result.sdkProjectedSHA}\nSDK_CI_BASE=${result.sdkProjectedBase ?? ''}\n` +
        `SDK_CI_ARTIFACT_DIR=${artifacts}\nSDK_CI_RECEIPT=${path.join(artifacts, 'receipt.json')}\nSDK_CI_TARBALL=${path.join(artifacts, filename)}\nSDK_CI_PROJECTION=${path.join(path.dirname(result.workspace), 'projection.qa.json')}\n`,
    );
}

if (isMainModule(import.meta.url)) {
  if (process.argv.length > 2)
    throw new Error('prepare-workspace takes configuration from SDK_BASE_REVISION');
  const base = process.env.SDK_BASE_REVISION || undefined;
  if (process.env.GITHUB_EVENT_NAME === 'pull_request' && !base)
    throw new Error('PR SDK base revision is required');
  const result = prepareWorkspace({ base });
  if (!process.env.GITHUB_ENV) throw new Error('GITHUB_ENV is required for workflow preparation');
  exportWorkspace(result);
  console.log(
    'Prepared an SDK-only Git workspace; private projection mapping retained outside source',
  );
}
