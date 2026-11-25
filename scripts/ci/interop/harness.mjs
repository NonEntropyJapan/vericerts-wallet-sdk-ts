import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import {
  lstatSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  realpathSync,
  writeFileSync,
} from 'node:fs';
import path from 'node:path';
import { listRepoFiles } from '../../lib/repo-files.mjs';
import { boundarySupportFiles } from '../../packed-consumer/boundary-files.mjs';
import { inside } from '../../packed-consumer/containment.mjs';

const ownTooling = [
  ...boundarySupportFiles.map((name) => `scripts/packed-consumer/${name}`),
  'scripts/ci/interop/node-reporter.mjs',
  'scripts/lib/is-main-module.mjs',
];
const hash = (bytes) => createHash('sha256').update(bytes).digest('hex');

export function inventoryInteropHarness(workspace, accept = () => {}) {
  const root = realpathSync(workspace);
  const harness = listRepoFiles(root, true).filter((name) => name.startsWith('test/interop/'));
  assert.ok(harness.length, 'No package Interop harness in the SDK source');
  const files = [...harness, ...ownTooling].sort().map((name) => {
    const parts = name.split('/');
    assert.ok(
      !/[\r\n\\]/.test(name) &&
        !parts.some((part) => ['..', '.git', 'node_modules'].includes(part)),
    );
    const file = path.join(root, name);
    const stat = lstatSync(file);
    assert.ok(
      stat.isFile() && realpathSync(file) === file,
      `Invalid Interop harness input: ${name}`,
    );
    const bytes = readFileSync(file);
    const mode = stat.mode & 0o111 ? 0o755 : 0o644;
    accept(name, bytes, mode);
    return { path: name, mode, sha256: hash(bytes) };
  });
  return { files, manifestSha256: hash(JSON.stringify(files)) };
}

export function copyInteropHarness(workspace, consumer) {
  const root = realpathSync(consumer);
  assert.ok(!inside(realpathSync(workspace), root), 'Interop consumer must be outside SDK source');
  assert.deepEqual(readdirSync(root), [], 'Interop consumer must start empty');
  return inventoryInteropHarness(workspace, (name, bytes, mode) => {
    const file = path.join(root, name);
    mkdirSync(path.dirname(file), { recursive: true });
    writeFileSync(file, bytes, { flag: 'wx', mode });
  });
}
