import { expect, test } from 'bun:test';
import { copyFileSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { boundarySupportFiles } from '../boundary-files.mjs';
import { run } from '../process.mjs';

for (const binary of ['node', 'bun']) {
  test(`${binary} preload preserves native inside module loading in a test run`, () => {
    const root = mkdtempSync(join(tmpdir(), 'sdk-preload-'));
    try {
      const support = join(root, 'scripts', 'packed-consumer');
      mkdirSync(support, { recursive: true });
      for (const name of boundarySupportFiles) {
        copyFileSync(new URL(`../${name}`, import.meta.url), join(support, name));
      }
      writeFileSync(join(root, 'own.cjs'), 'exports.value = 42;');
      writeFileSync(
        join(root, 'inside.test.mjs'),
        `import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { test } from '${binary === 'node' ? 'node:test' : 'bun:test'}';
import ownDefault, { value } from './own.cjs';
process.once('beforeExit', () => console.log('inside preload beforeExit'));
test('inside module uses native namespace and cache', async () => {
  const require = createRequire(import.meta.url);
  assert.equal(value, 42);
  assert.equal(require('./own.cjs'), ownDefault);
  assert.equal((await import('./own.cjs')).default, ownDefault);
  console.log('inside preload verified');
});
`,
      );
      const preload = join(support, `preload-${binary}.mjs`);
      const args =
        binary === 'node'
          ? ['--import', preload, '--test', './inside.test.mjs']
          : ['test', '--preload', preload, './inside.test.mjs'];
      const output = run(binary, args, root);
      expect(output).toContain('inside preload verified');
      if (binary === 'node') expect(output).toContain('inside preload beforeExit');
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
}
