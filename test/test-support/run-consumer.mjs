import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { verifyMaterials } from './verify.mjs';

const args = process.argv.slice(2);
if (args.length !== 4 || args[0] !== '--sdk-tgz' || args[2] !== '--materials') {
  throw new Error(
    'Usage: node test/test-support/run-consumer.mjs --sdk-tgz <tgz> --materials <exported-directory>',
  );
}
const tgz = resolve(args[1]);
const materials = resolve(args[3]);
const manifest = verifyMaterials(materials);
const root = mkdtempSync(join(tmpdir(), 'sdk-material-consumer-'));
const run = (command, arguments_) => {
  const result = spawnSync(command, arguments_, {
    cwd: root,
    encoding: 'utf8',
    env: { ...process.env, NODE_PATH: '', NODE_OPTIONS: '' },
  });
  if (result.status !== 0) throw new Error(`${command} failed\n${result.stdout}\n${result.stderr}`);
  process.stdout.write(result.stdout);
};
try {
  writeFileSync(join(root, 'package.json'), JSON.stringify({ private: true, type: 'module' }));
  cpSync(materials, join(root, 'materials'), { recursive: true });
  run('npm', [
    'install',
    '--ignore-scripts',
    '--legacy-peer-deps',
    '--no-audit',
    '--no-fund',
    tgz,
    'typescript@5.9.3',
  ]);
  const require = createRequire(join(root, 'package.json'));
  const pkg = JSON.parse(
    readFileSync(require.resolve('@vericerts/vericerts-wallet-sdk/package.json'), 'utf8'),
  );
  assert.equal(`${pkg.name}@${pkg.version}`, manifest.generatedFrom);
  run(process.execPath, ['materials/consumer.mjs']);
  run(process.execPath, ['materials/tools-consumer.mjs']);
} finally {
  rmSync(root, { recursive: true, force: true });
}
