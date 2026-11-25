import { existsSync, realpathSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const sdk = realpathSync(fileURLToPath(new URL('../../', import.meta.url)));
const inside = (root, target) => {
  const relative = path.relative(root, target);
  return (
    relative === '' ||
    (!path.isAbsolute(relative) && relative !== '..' && !relative.startsWith(`..${path.sep}`))
  );
};
export function noticeInput(input, { modulesOnly = false, allowMissing = false } = {}) {
  const name = path.resolve(input instanceof URL ? fileURLToPath(input) : input);
  const actual = existsSync(name)
    ? realpathSync(name)
    : allowMissing
      ? path.join(realpathSync(path.dirname(name)), path.basename(name))
      : realpathSync(name);
  if (!inside(sdk, actual)) throw new Error('NOTICE input escapes SDK');
  if (modulesOnly) {
    const modules = realpathSync(path.join(sdk, 'node_modules'));
    if (!inside(sdk, modules) || !inside(modules, actual))
      throw new Error('NOTICE package escapes SDK node_modules');
  }
  return actual;
}
