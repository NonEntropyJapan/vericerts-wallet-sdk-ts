import assert from 'node:assert/strict';
import { realpathSync } from 'node:fs';
import { plugin } from 'bun';

export function installBunBoundary() {
  const cwd = process.cwd();
  const root = realpathSync(cwd);
  const aliases = new Set([root, cwd]);
  if (process.env.PWD && realpathSync(process.env.PWD) === root) aliases.add(process.env.PWD);
  const escapeRegExp = (path) => path.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const outside = new RegExp(`^(?!(?:${[...aliases].map(escapeRegExp).join('|')})(?:/|$))`);
  let violations = 0;
  const failExit = () => {
    if (violations && !process.exitCode) process.exitCode = 1;
  };
  plugin({
    name: 'isolated-consumer-module-boundary',
    setup(builder) {
      // Inside files never enter onLoad: Bun keeps its exact default loader and
      // CJS exports. Bun resolves symlinks before matching the file path filter.
      builder.onLoad({ filter: outside, namespace: 'file' }, () => {
        violations++;
        // Bun's test runner may exit without emitting beforeExit.
        failExit();
        throw new Error('Module escapes isolated consumer');
      });
    },
  });
  process.once('beforeExit', failExit);
  return () => assert.equal(violations, 0, 'Module attempted to leave isolated consumer');
}
