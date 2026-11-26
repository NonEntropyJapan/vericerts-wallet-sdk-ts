import { afterEach, expect, test } from 'bun:test';
import {
  appendFileSync,
  copyFileSync,
  cpSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { join } from 'node:path';
import { inspectArtifact } from './archive.mjs';
import { fixture } from './artifact-fixtures.mjs';
import { parseArgs } from './cli.mjs';
import { isolatedEnv, run } from './process.mjs';
import { readReceipt, requireReleaseChecks, saveReceipt } from './receipt.mjs';
import { dryRunRelease, plannedReleaseTag } from './release.mjs';

const roots = [];
function setup() {
  const f = fixture();
  roots.push(f.root);
  return f;
}
afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

test('packlist and relative declarations are checked from actual tgz bytes', () => {
  const f = setup();
  expect(inspectArtifact(f.tarball).artifact.exports).toEqual(['.', './package.json']);
  writeFileSync(join(f.packageRoot, 'dist/index.d.ts'), 'export * from "./missing.js";');
  f.repack();
  expect(() => inspectArtifact(f.tarball)).toThrow('Missing relative declaration');
});

test('tar symlinks cannot point to producer files', () => {
  const f = setup();
  symlinkSync('/producer/node_modules', join(f.packageRoot, 'dist/producer'));
  f.repack();
  expect(() => inspectArtifact(f.tarball)).toThrow('Tar links');
});

test('hidden metadata, duplicate entries and a truncated archive are rejected', () => {
  let f = setup();
  writeFileSync(join(f.packageRoot, '._NOTICE'), 'private metadata');
  f.repack();
  expect(() => inspectArtifact(f.tarball)).toThrow('Unexpected packed file');
  f = setup();
  run('tar', ['-czf', f.tarball, '-C', f.root, 'package', 'package/NOTICE'], f.root);
  expect(() => inspectArtifact(f.tarball)).toThrow('Duplicate');
  f = setup();
  writeFileSync(f.tarball, readFileSync(f.tarball).subarray(0, 40));
  expect(() => inspectArtifact(f.tarball)).toThrow();
});

test('absolute declaration paths cannot resolve into the producer', () => {
  const f = setup();
  writeFileSync(
    join(f.packageRoot, 'dist/index.d.ts'),
    'export * from "/producer/node_modules/private.d.ts";',
  );
  f.repack();
  expect(() => inspectArtifact(f.tarball)).toThrow('Absolute declaration reference');
});

test('missing JS or d.ts export targets are rejected', () => {
  for (const name of ['index.js', 'index.d.ts']) {
    const f = setup();
    rmSync(join(f.packageRoot, `dist/${name}`));
    f.repack();
    expect(() => inspectArtifact(f.tarball)).toThrow('Missing export target');
  }
});

test('receipt binds source SHA and exact tgz digest before npm can run', () => {
  const f = setup();
  let invoked = false;
  const execute = () => {
    invoked = true;
  };
  expect(() => dryRunRelease({ ...f.options, 'source-sha': 'e'.repeat(40) }, execute)).toThrow(
    'source SHA mismatch',
  );
  appendFileSync(f.tarball, '\n');
  expect(() => dryRunRelease(f.options, execute)).toThrow('identity/digest mismatch');
  expect(invoked).toBe(false);
});

test('dirty, failed, incomplete or public-provenance receipts cannot pass private dry-run gate', () => {
  const f = setup();
  const clone = () => structuredClone(f.receipt);
  let x = clone();
  x.source.privateRevision.clean = false;
  expect(() => requireReleaseChecks(x)).toThrow('Dirty-source');
  x = clone();
  x.checks.node[0].status = 'failed';
  expect(() => requireReleaseChecks(x)).toThrow('Incomplete/failed');
  x = clone();
  x.checks.node.shift();
  expect(() => requireReleaseChecks(x)).toThrow('Missing Node 20.19.0');
  x = clone();
  x.checks.browser.status = 'not-run';
  expect(() => requireReleaseChecks(x)).toThrow('Browser consumers');
  x = clone();
  x.source.publicRevision = { sha: 'f'.repeat(40) };
  saveReceipt(f.receiptPath, x);
  expect(() => readReceipt(f.receiptPath)).toThrow('Public revision is not approved');
});

test('actual npm dry-run uses the verified tgz without executing build/publish lifecycle hooks', () => {
  const f = setup();
  const before = readFileSync(f.tarball);
  const output = JSON.parse(dryRunRelease(f.options));
  expect(output['@vericerts/vericerts-wallet-sdk'].name).toBe('@vericerts/vericerts-wallet-sdk');
  expect(readFileSync(f.tarball)).toEqual(before);
});

test('SDK tag keeps the exact release or prerelease version accepted for a packed artifact', () => {
  expect(plannedReleaseTag('0.1.0')).toBe('v0.1.0');
  expect(plannedReleaseTag('1.0.0-rc.1')).toBe('v1.0.0-rc.1');
  for (const invalid of [
    'v0.1.0',
    '0.01.0',
    '9007199254740992.0.0',
    '1.0.0-rc.01',
    '1.0.0-rc..1',
    '1.0.0-rc_test',
    '1.0.0+build',
    `1.0.0-${'a'.repeat(251)}`,
    '0.1.0\n',
  ]) {
    expect(() => plannedReleaseTag(invalid)).toThrow();
  }
});

test('dry-run CLI works without a producer package, dependencies, Git or producer module', () => {
  const f = setup();
  const tools = join(f.root, 'portable');
  cpSync(new URL('.', import.meta.url), tools, { recursive: true });
  rmSync(join(tools, 'producer.mjs'));
  copyFileSync(f.receiptPath, join(tools, 'receipt.json'));
  const output = run(
    'node',
    [
      join(tools, 'release.mjs'),
      `--tarball=${f.tarball}`,
      `--receipt=${join(tools, 'receipt.json')}`,
      `--source-sha=${f.options['source-sha']}`,
    ],
    f.root,
    { NODE_PATH: '/producer/node_modules', NODE_OPTIONS: '--require=/producer/private.cjs' },
  );
  expect(output).toContain('private validation only');
  expect(output).toContain('@vericerts/vericerts-wallet-sdk@0.0.0');
  expect(output).toContain('Planned Git tag v0.0.0');
  expect(output).toContain(`tarball SHA-256 ${f.receipt.artifact.sha256}`);
});

test('existing artifact mode requires receipt and explicit source SHA and refuses repacking options', () => {
  expect(() => parseArgs(['--tarball=x'])).toThrow('receipt');
  expect(() => parseArgs(['--tarball=x', '--receipt=y'])).toThrow('source-sha');
  expect(() =>
    parseArgs(['--tarball=x', '--receipt=y', `--source-sha=${'a'.repeat(40)}`, '--artifact-dir=z']),
  ).toThrow('cannot repack');
  expect(() => parseArgs(['--tarball=x', '--tarball=y'])).toThrow('Duplicate');
  expect(() => parseArgs(['--receipt='])).toThrow('Unknown/empty');
  expect(isolatedEnv({ NODE_PATH: '/producer', NODE_OPTIONS: '--require=private' }).NODE_PATH).toBe(
    '',
  );
});

test('an actual existing-artifact CLI failure invalidates its previous success flags', () => {
  const f = setup();
  const tools = join(f.root, 'portable');
  cpSync(new URL('.', import.meta.url), tools, { recursive: true });
  rmSync(join(tools, 'producer.mjs'));
  f.receipt.tooling.bun = '0.0.0';
  saveReceipt(f.receiptPath, f.receipt);
  expect(() =>
    run(
      'node',
      [
        join(tools, 'run.mjs'),
        `--tarball=${f.tarball}`,
        `--receipt=${f.receiptPath}`,
        `--source-sha=${f.options['source-sha']}`,
        '--bun',
      ],
      f.root,
    ),
  ).toThrow('Bun version differs from receipt');
  const failed = readReceipt(f.receiptPath);
  expect(failed.checks.node.at(-1).status).toBe('failed');
  expect(failed.checks.bun.status).toBe('failed');
  expect(() => requireReleaseChecks(failed)).toThrow('Incomplete/failed Node consumer');
});
