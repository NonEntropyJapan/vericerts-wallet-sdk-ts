import assert from 'node:assert/strict';
import { copyFileSync, existsSync, mkdirSync, realpathSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { boundarySupportFiles } from './boundary-files.mjs';
import { checkSdkSyntax } from './preflight.mjs';
import { installArgs, run } from './process.mjs';
import { checkTypes } from './types.mjs';

export function checkNode(root, tarball, pkg, typescript, bunVersion) {
  assert.ok(!process.versions.bun, 'Run this consumer with Node, not its Bun compatibility layer');
  const [major, minor] = process.versions.node.split('.').map(Number);
  assert.ok(major > 20 || (major === 20 && minor >= 19), 'Node >=20.19.0 is required');
  const consumer = join(root, 'node');
  mkdirSync(consumer);
  writeFileSync(join(consumer, 'package.json'), '{"private":true,"type":"module"}\n');
  if (bunVersion)
    assert.equal(
      run('bun', ['--version'], consumer).trim(),
      bunVersion,
      'Bun version differs from receipt',
    );
  run('npm', [...installArgs, tarball, `typescript@${typescript}`], consumer);
  const installed = join(consumer, 'node_modules', pkg.name);
  assert.equal(
    realpathSync(installed),
    join(realpathSync(join(consumer, 'node_modules')), pkg.name),
  );
  assert.equal(existsSync(join(installed, 'src')), false);
  for (const peer of Object.keys(pkg.peerDependencies)) {
    assert.equal(existsSync(join(consumer, 'node_modules', peer)), false);
  }
  checkSdkSyntax(consumer, installed);
  for (const name of [
    'runtime.mjs',
    'runtime-node.mjs',
    'runtime-bun.mjs',
    ...boundarySupportFiles,
  ]) {
    copyFileSync(new URL(`./${name}`, import.meta.url), join(consumer, name));
  }
  const execute = (command, args) => run(command, args, consumer);
  for (const format of ['esm', 'cjs']) execute(process.execPath, ['runtime-node.mjs', format]);
  if (bunVersion) for (const format of ['esm', 'cjs']) execute('bun', ['runtime-bun.mjs', format]);
  checkTypes(pkg, consumer, execute, false);
  run(
    'npm',
    [
      ...installArgs,
      ...Object.entries(pkg.peerDependencies).map(([name, version]) => `${name}@${version}`),
    ],
    consumer,
  );
  for (const format of ['esm', 'cjs'])
    execute(process.execPath, ['runtime-node.mjs', format, 'otel']);
  if (bunVersion)
    for (const format of ['esm', 'cjs']) execute('bun', ['runtime-bun.mjs', format, 'otel']);
  checkTypes(pkg, consumer, execute, true);
  return {
    status: 'passed',
    version: process.versions.node,
    formats: ['esm', 'cjs'],
    strictTypeModes: 5,
    optionalPeers: ['absent', 'installed'],
    ...(bunVersion
      ? {
          bun: {
            status: 'passed',
            version: bunVersion,
            formats: ['esm', 'cjs'],
            optionalPeers: ['absent', 'installed'],
          },
        }
      : {}),
  };
}
