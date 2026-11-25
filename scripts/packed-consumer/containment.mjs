import assert from 'node:assert/strict';
import { existsSync, realpathSync } from 'node:fs';
import { createRequire } from 'node:module';
import { isAbsolute, join, relative, sep } from 'node:path';

export function inside(root, path) {
  const rel = relative(root, path);
  return rel === '' || (!isAbsolute(rel) && rel !== '..' && !rel.startsWith(`..${sep}`));
}

export function containedFile(root, path) {
  const base = realpathSync(root);
  assert.ok(existsSync(path), 'Missing consumer module');
  const actual = realpathSync(path);
  assert.ok(inside(base, actual), 'Module escapes isolated consumer');
  return actual;
}

export function ownTypeScript(consumer) {
  const require = createRequire(join(consumer, 'package.json'));
  const compiler = containedFile(consumer, require.resolve('typescript'));
  return require(compiler);
}
