import { SOURCE_EXTENSION_RE } from '../source-extensions.mjs';
import { definesTests, hasExecutableTypeScript, hasValueExport } from './executable-typescript.mjs';

const NON_SOURCE_PATH = /(?:^|\/)(?:__tests__|e2e|node_modules)\/|\.d\.ts$/;
const TEST_FILE_NAME = /\.(?:test|spec)\.[^/]+$/;
const TS_LIKE = /\.(?:tsx?|[mc]?js)$/;
export function isUncoveredSourceCandidate(file, source) {
  if (!SOURCE_EXTENSION_RE.test(file) || NON_SOURCE_PATH.test(file)) return false;
  if (typeof source !== 'string') return false;
  if (!TS_LIKE.test(file)) return true;
  if (TEST_FILE_NAME.test(file) && definesTests(source, file) && !hasValueExport(source, file)) {
    return false;
  }
  return hasExecutableTypeScript(source, file);
}
export function testFileExports(file, source) {
  return (
    SOURCE_EXTENSION_RE.test(file) &&
    TS_LIKE.test(file) &&
    TEST_FILE_NAME.test(file) &&
    typeof source === 'string' &&
    definesTests(source, file) &&
    hasValueExport(source, file)
  );
}
export function isCountedPath(file) {
  return !NON_SOURCE_PATH.test(file);
}
