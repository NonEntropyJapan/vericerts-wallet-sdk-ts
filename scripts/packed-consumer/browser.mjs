import assert from 'node:assert/strict';
import { copyFileSync, mkdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { digest } from './archive.mjs';
import { installArgs, run } from './process.mjs';

const fixture = fileURLToPath(new URL('../../test/browser-consumer/', import.meta.url));

export function browserTooling() {
  return {
    dependencies: JSON.parse(readFileSync(join(fixture, 'package.json'), 'utf8')).devDependencies,
    lockSha256: digest(readFileSync(join(fixture, 'package-lock.json'))),
  };
}

export function checkBrowser(root, tarball, pkg, tooling) {
  assert.deepEqual(browserTooling(), tooling, 'Browser tooling does not match receipt');
  const consumer = join(root, 'browser');
  mkdirSync(consumer);
  for (const file of [
    'package.json',
    'package-lock.json',
    'index.html',
    'otel.html',
    'probe.mjs',
    'otel.mjs',
    'run.mjs',
    'boundary.mjs',
    'boundary-regression.mjs',
  ]) {
    copyFileSync(join(fixture, file), join(consumer, file));
  }
  run(
    'npm',
    [
      'ci',
      '--ignore-scripts',
      '--legacy-peer-deps',
      '--no-audit',
      '--no-fund',
      '--workspaces=false',
    ],
    consumer,
  );
  run('npm', [...installArgs, '--no-save', tarball], consumer);
  const outputs = [run(process.execPath, ['run.mjs'], consumer)];
  run(
    'npm',
    [
      ...installArgs,
      '--no-save',
      tarball,
      ...Object.entries(pkg.peerDependencies).map(([name, version]) => `${name}@${version}`),
    ],
    consumer,
  );
  outputs.push(run(process.execPath, ['run.mjs', '--otel'], consumer));
  for (const output of outputs) console.log(output.trim());
  return {
    status: 'passed',
    optionalPeers: ['absent', 'installed'],
    chromium: outputs.map((output) => /Chromium (.+)/.exec(output)?.[1]),
    node: process.versions.node,
  };
}
