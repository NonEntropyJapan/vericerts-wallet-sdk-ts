import { realpathSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
export function isMainModule(url) {
  return (
    Boolean(process.argv[1]) && realpathSync(process.argv[1]) === realpathSync(fileURLToPath(url))
  );
}
