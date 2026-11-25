import { readFileSync } from 'node:fs';
import path from 'node:path';
import { listRepoFiles } from '../repo-files.mjs';

const SCRIPT = /\.[cm]?[jt]sx?$/;
const TEST = /(?:\.|_)(?:test|spec)\.[^/]+$/;
const DIRS = new Set(['__tests__', 'test', 'tests', 'testing', 'e2e']);
const RUNNER =
  /['"`](?:node:test|bun:test|vitest|@playwright\/test|@jest\/globals|mocha|jest)['"`]/;
export const listAllFiles = (root = '.') => listRepoFiles(root);
export function listTestFiles(root = '.') {
  return listAllFiles(root).filter(
    (file) =>
      SCRIPT.test(file) &&
      (TEST.test(file) ||
        file
          .split('/')
          .slice(0, -1)
          .some((part) => DIRS.has(part)) ||
        RUNNER.test(readFileSync(path.join(root, file), 'utf8'))),
  );
}
