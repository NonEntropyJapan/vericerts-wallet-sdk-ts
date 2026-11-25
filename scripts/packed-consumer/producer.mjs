import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, readdirSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { inspectArtifact } from './archive.mjs';
import { browserTooling } from './browser.mjs';
import { run } from './process.mjs';
import { newReceipt, sourceIdentity } from './receipt.mjs';

export function produceArtifact(options) {
  const sdk = fileURLToPath(new URL('../..', import.meta.url));
  const artifacts = options['artifact-dir'] ?? mkdtempSync(join(tmpdir(), 'sdk-packed-artifact-'));
  mkdirSync(artifacts, { recursive: true });
  assert.deepEqual(readdirSync(artifacts), [], 'Artifact output directory must be empty');
  const source = sourceIdentity(sdk, options['source-sha'], options.validationOrigin);
  const lock = readFileSync(join(sdk, 'bun.lock'), 'utf8');
  const lockedTypeScript = [...lock.matchAll(/^\s*"typescript": \["typescript@([^"]+)"/gm)];
  assert.equal(lockedTypeScript.length, 1, 'Expected one locked TypeScript version');
  const typescript = JSON.parse(
    readFileSync(join(sdk, 'node_modules/typescript/package.json'), 'utf8'),
  ).version;
  assert.equal(
    typescript,
    lockedTypeScript[0][1],
    'Installed TypeScript is not the locked version',
  );
  run('npm', ['pack', '--pack-destination', artifacts], sdk);
  const tarballs = readdirSync(artifacts).filter((name) => name.endsWith('.tgz'));
  assert.equal(tarballs.length, 1, 'Expected exactly one packed tarball');
  assert.ok(
    JSON.stringify(sourceIdentity(sdk, options['source-sha'], options.validationOrigin)) ===
      JSON.stringify(source),
    'Source changed while packing',
  );
  const tarball = join(artifacts, tarballs[0]);
  const { artifact } = inspectArtifact(tarball);
  return {
    tarball,
    receiptPath: options.receipt ?? join(artifacts, 'receipt.json'),
    receipt: newReceipt(artifact, tarball, source, {
      typescript,
      browser: browserTooling(),
      bun: run('bun', ['--version'], sdk).trim(),
    }),
  };
}
