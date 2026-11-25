// cdxgen の入力を SDK 直下の npm manifest と Bun lockfile に限定する。
import { execFileSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import lockfile from '../bun.lock' with { type: 'jsonc' };
import { prepareSdkBom } from './sdk-bom.mjs';

const outputDir = resolve('sbom');
mkdirSync(outputDir, { recursive: true });
const staging = mkdtempSync(join(outputDir, 'pack-'));
const output = join(staging, 'sdk.cdx.json');
try {
  execFileSync(
    'bunx',
    [
      '@cyclonedx/cdxgen@12.8.4',
      '-t',
      'bun',
      '--no-recurse',
      '--no-babel',
      '--no-install-deps',
      '--fail-on-error',
      '--spec-version',
      '1.5',
      '-o',
      output,
      '.',
    ],
    { stdio: 'inherit', env: { ...process.env, FETCH_LICENSE: 'true' } },
  );

  const pkg = JSON.parse(readFileSync('package.json', 'utf8'));
  const bom = prepareSdkBom(
    readFileSync(output, 'utf8'),
    pkg,
    lockfile.packages,
    resolve('bun.lock'),
  );
  writeFileSync(output, `${JSON.stringify(bom, null, 2)}\n`);
  renameSync(output, join(outputDir, 'sdk.cdx.json'));
} finally {
  rmSync(staging, { recursive: true, force: true });
}
