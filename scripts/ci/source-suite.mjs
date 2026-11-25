import assert from 'node:assert/strict';
import { mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { checkResultFiles } from '../check-test-results.mjs';
import { isMainModule } from '../lib/is-main-module.mjs';
import { parseBunJunit } from '../lib/result-gate/parse.mjs';
import { requireValidationOrigin } from '../packed-consumer/source-origin.mjs';
import { execute } from './environment.mjs';
import {
  currentSuiteManifest,
  requireStableSuite,
  validateSuiteResults,
} from './suite-manifest.mjs';

export function runSourceSuite({
  cwd = process.cwd(),
  coverage = true,
  manifest = currentSuiteManifest(cwd),
  run = execute,
} = {}) {
  requireStableSuite(cwd, manifest);
  mkdirSync(path.join(cwd, 'coverage'), { recursive: true });
  rmSync(path.join(cwd, 'coverage/junit.xml'), { force: true });
  rmSync(path.join(cwd, 'coverage/source-suite-result.json'), { force: true });
  writeFileSync(
    path.join(cwd, 'coverage/execution-manifest.json'),
    `${JSON.stringify(manifest, null, 2)}\n`,
  );
  const args = [
    'test',
    ...manifest.suites.source.map((file) => `./${file}`),
    ...(coverage ? ['--coverage', '--coverage-reporter=lcov', '--coverage-reporter=text'] : []),
    '--reporter=junit',
    '--reporter-outfile=coverage/junit.xml',
  ];
  run('bun', args, cwd, { stdio: 'inherit' });
  requireStableSuite(cwd, manifest);
  const report = parseBunJunit(readFileSync(path.join(cwd, 'coverage/junit.xml'), 'utf8'), cwd);
  const problems = checkResultFiles({
    bun: path.join(cwd, 'coverage/junit.xml'),
    cwd,
    expectedFiles: manifest.suites.source,
  });
  if (problems.length) throw new Error(problems.join('\n'));
  const fragment = {
    suite: 'source',
    source: manifest.source,
    report: { ...report, files: [...report.files] },
  };
  writeFileSync(
    path.join(cwd, 'coverage/source-suite-result.json'),
    `${JSON.stringify(fragment)}\n`,
  );
  if (!manifest.suites.packageInterop.length)
    validateSuiteResults(manifest, [{ ...fragment, report }]);
  return { manifest, fragment, command: { executable: 'bun', args } };
}

if (isMainModule(import.meta.url)) {
  const [option, coverage, ...rest] = process.argv.slice(2);
  const origin = /^--validation-origin=(.+)$/.exec(option ?? '')?.[1];
  assert.ok(
    !rest.length && (!coverage || coverage === '--coverage'),
    'Invalid source suite options',
  );
  const cwd = process.cwd();
  const manifest = currentSuiteManifest(cwd, requireValidationOrigin(origin));
  runSourceSuite({ cwd, manifest, coverage: Boolean(coverage) });
}
