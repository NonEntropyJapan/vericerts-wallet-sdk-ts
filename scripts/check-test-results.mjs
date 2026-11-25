import { readFileSync } from 'node:fs';
import { isMainModule } from './lib/is-main-module.mjs';
import { listRepoFiles } from './lib/repo-files.mjs';
import { checkTestResults, expectedTestFiles } from './lib/result-gate/check.mjs';
import { parseBunJunit } from './lib/result-gate/parse.mjs';
export function checkResultFiles({ bun, cwd = process.cwd(), expectedFiles }) {
  if (!bun) return ['--bun=<junit.xml> is required'];
  const expected = expectedFiles ?? expectedTestFiles(listRepoFiles(cwd), '', ['node_modules']);
  if (expected.length === 0) return ['No expected SDK test files'];
  return checkTestResults(parseBunJunit(readFileSync(bun, 'utf8'), cwd), {
    expectedFiles: expected,
    label: 'bun test',
  });
}
if (isMainModule(import.meta.url)) {
  const argv = process.argv.slice(2);
  if (argv.length !== 1 || !argv[0].startsWith('--bun='))
    throw new Error('usage: --bun=<junit.xml>');
  const problems = checkResultFiles({ bun: argv[0].slice(6) });
  if (problems.length) throw new Error(problems.join('\n'));
  console.log('check-test-results: OK');
}
