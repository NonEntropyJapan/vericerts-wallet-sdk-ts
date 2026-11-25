import { readFileSync, realpathSync } from 'node:fs';
import { createRequire } from 'node:module';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../../', import.meta.url));
const modules = path.join(root, 'node_modules');
const own = path.join(modules, 'typescript');
const relative = path.relative(realpathSync(modules), realpathSync(own));
if (
  relative.startsWith('..') ||
  path.isAbsolute(relative) ||
  realpathSync(modules) !== path.resolve(modules)
) {
  throw new Error('TypeScript must be installed inside this SDK node_modules');
}
const declared = JSON.parse(readFileSync(path.join(root, 'package.json'), 'utf8')).devDependencies
  .typescript;
const installed = JSON.parse(readFileSync(path.join(own, 'package.json'), 'utf8')).version;
if (declared !== installed) throw new Error('SDK TypeScript must match its exact devDependency');
export const ts = createRequire(path.join(root, 'package.json'))('./node_modules/typescript');
