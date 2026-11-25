import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { lstatSync, mkdirSync, readFileSync, realpathSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { git, listRepoFiles } from '../../lib/repo-files.mjs';
import { inside } from '../../packed-consumer/containment.mjs';
import { DEVELOPMENT_SNAPSHOT } from '../../packed-consumer/source-origin.mjs';
import { execute } from '../environment.mjs';
import { snapshot } from '../git-projection.mjs';

const generated = new Set(['.git', 'node_modules', 'dist', 'coverage', 'sbom']);
const digest = (bytes) => createHash('sha256').update(bytes).digest('hex');

export function sourceInputs(sdk, accept = () => {}) {
  const root = realpathSync(sdk);
  const files = listRepoFiles(root).filter(
    (name) => !name.split('/').some((part) => generated.has(part)),
  );
  assert.ok(files.length, 'No SDK inputs to snapshot');
  return files.map((name) => {
    assert.ok(!/[\r\n\\]/.test(name) && !path.isAbsolute(name), 'Nonportable SDK input path');
    const file = path.join(root, name);
    assert.equal(realpathSync(file), file, `SDK input traverses a link: ${name}`);
    const stat = lstatSync(file);
    assert.ok(stat.isFile(), `SDK input is not a regular file: ${name}`);
    const bytes = readFileSync(file);
    const mode = stat.mode & 0o111 ? 0o755 : 0o644;
    accept(name, bytes, mode);
    const gitBlob = createHash('sha1').update(`blob ${bytes.length}\0`).update(bytes).digest('hex');
    return { path: name, mode, bytes: bytes.length, sha256: digest(bytes), gitBlob };
  });
}

export function requireUnchangedInputs(sdk, inputs) {
  assert.deepEqual(sourceInputs(sdk), inputs, 'SDK inputs changed during isolated validation');
}

export function createLocalSnapshot(sdk, output) {
  const repo = realpathSync(git(sdk, ['rev-parse', '--show-toplevel']).trim());
  assert.ok(!inside(repo, realpathSync(output)), 'Snapshot must be outside the producer checkout');
  const originalHead = git(sdk, ['rev-parse', 'HEAD']).trim();
  const originalDirty =
    git(sdk, ['status', '--porcelain', '--untracked-files=all', '--', '.']).length > 0;
  const workspace = path.join(output, 'sdk');
  mkdirSync(workspace);
  const inputs = sourceInputs(sdk, (name, bytes, mode) => {
    const file = path.join(workspace, name);
    mkdirSync(path.dirname(file), { recursive: true });
    writeFileSync(file, bytes, { flag: 'wx', mode });
  });
  requireUnchangedInputs(sdk, inputs);
  execute('git', ['init', '-q', '--initial-branch=validation'], workspace);
  const sdkProjectedSHA = snapshot(workspace, 'SDK development snapshot');
  const sdkTree = git(workspace, ['rev-parse', 'HEAD^{tree}']).trim();
  const treeEntries = new Map(
    git(workspace, ['ls-tree', '-r', '-z', 'HEAD'])
      .split('\0')
      .filter(Boolean)
      .map((entry) => {
        const tab = entry.indexOf('\t');
        return [entry.slice(tab + 1), entry.slice(0, tab)];
      }),
  );
  assert.equal(treeEntries.size, inputs.length, 'SDK snapshot tree file set differs');
  for (const input of inputs) {
    assert.equal(
      treeEntries.get(input.path),
      `100${input.mode.toString(8)} blob ${input.gitBlob}`,
      `SDK snapshot tree does not contain exact input bytes and mode: ${input.path}`,
    );
  }
  assert.deepEqual(sourceInputs(workspace), inputs, 'SDK snapshot bytes or modes differ');
  assert.deepEqual(git(workspace, ['status', '--porcelain', '--untracked-files=all']), '');
  const provenance = {
    validationOrigin: DEVELOPMENT_SNAPSHOT,
    originalHead,
    originalDirty,
    sdkProjectedSHA,
    sdkTree,
    inputSha256: digest(JSON.stringify(inputs)),
    inputs,
  };
  writeFileSync(path.join(output, 'development-snapshot.json'), `${JSON.stringify(provenance)}\n`, {
    flag: 'wx',
  });
  return { workspace, ...provenance };
}
