import { realpathSync } from 'node:fs';
import path from 'node:path';

export function normalizeSourcePath(file, cwd) {
  const slashed = file.replaceAll('\\', '/');
  if (path.isAbsolute(slashed)) {
    try {
      const relative = path.relative(realpathSync(cwd), realpathSync(slashed));
      if (
        !path.isAbsolute(relative) &&
        relative !== '..' &&
        !relative.startsWith(`..${path.sep}`)
      ) {
        return relative.split(path.sep).join('/');
      }
    } catch {
      // A nonexistent foreign path must never be rescued by its source suffix.
    }
    return slashed;
  }
  return path.posix.normalize(slashed);
}
export const createSourcePathNormalizer = (cwd) => (file) => normalizeSourcePath(file, cwd);
