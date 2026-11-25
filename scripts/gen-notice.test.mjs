import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

test('NOTICE uses bundled bytes, preserves nested versions and requires license texts', (t) => {
  const sdk = mkdtempSync(join(tmpdir(), 'sdk-notice-'));
  t.after(() => rmSync(sdk, { recursive: true, force: true }));
  const dependency = 'node_modules/sample';
  const nested = 'node_modules/sample/node_modules/sample';
  for (const [dir, version] of [
    [dependency, '2'],
    [nested, '1'],
  ]) {
    const root = join(sdk, dir);
    mkdirSync(root, { recursive: true });
    writeFileSync(join(root, 'package.json'), JSON.stringify({ name: 'sample', version }));
    writeFileSync(join(root, 'index.js'), '// Copyright 2024 Sample contributors');
    writeFileSync(join(root, 'LICENSE'), 'Sample license terms');
    writeFileSync(join(root, 'NOTICE.md'), 'Dataset attribution');
  }
  for (const [build, directory] of [
    ['esm', dependency],
    ['cjs', nested],
    ['otel', nested],
  ]) {
    const inputs = {
      [`${directory}/index.js`]: { bytesInOutput: 17 },
      'node_modules/tree-shaken/index.js': { bytesInOutput: 0 },
    };
    writeFileSync(
      join(sdk, `.build-meta-${build}.json`),
      JSON.stringify({ outputs: { js: { inputs } } }),
    );
  }

  const scripts = join(sdk, 'scripts');
  mkdirSync(join(scripts, 'lib'), { recursive: true });
  for (const file of ['gen-notice.mjs', 'lib/notice-boundary.mjs']) {
    copyFileSync(new URL(`./${file}`, import.meta.url), join(scripts, file));
  }
  const script = join(scripts, 'gen-notice.mjs');
  const generate = () => spawnSync('node', [script], { cwd: sdk, encoding: 'utf8' });
  const result = generate();
  assert.equal(result.status, 0, result.stderr);
  const notice = readFileSync(join(sdk, 'NOTICE'), 'utf8');
  assert.match(notice, /sample@1/);
  assert.match(notice, /sample@2/);
  assert.match(notice, /Copyright 2024 Sample contributors/);
  assert.match(notice, /Sample license terms/);
  assert.match(notice, /Dataset attribution/);
  assert.doesNotMatch(notice, /tree-shaken/);

  rmSync(join(sdk, nested, 'LICENSE'));
  const missing = generate();
  assert.notEqual(missing.status, 0);
  assert.match(missing.stderr, /Missing license text for sample@1/);
});
