import { mkdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { checkResultFiles } from '../check-test-results.mjs';
import { isMainModule } from '../lib/is-main-module.mjs';
import { listRepoFiles } from '../lib/repo-files.mjs';
import { expectedTestFiles } from '../lib/result-gate/check.mjs';
import { execute } from './environment.mjs';
import { validRevision } from './git-projection.mjs';
import { runSourceSuite } from './source-suite.mjs';

export const CONFORMANCE_SUITES = [
  ['vc', ['src/internal/credential/vc', 'src/internal/credential/presentation']],
  ['pe', ['src/internal/presentation-exchange']],
  ['haip', ['src/internal/credential/sdjwt']],
  ['oid4vci', ['src/internal/auth/oid4vci']],
  [
    'oid4vp',
    [
      'src/internal/auth/siop',
      'src/internal/auth/oid4vp-par',
      'src/internal/auth/__tests__/oid4vp',
    ],
  ],
];

export function runProfile(profile, { cwd = process.cwd(), base, executeCommand = execute } = {}) {
  if (!['static', 'unit', 'conformance', 'node'].includes(profile))
    throw new Error('Unknown SDK validation profile');
  if (base && !validRevision(base)) throw new Error('SDK diff base must be an exact SHA');
  const records = [];
  const run = (command, args) => {
    const started = Date.now();
    executeCommand(command, args, cwd, { stdio: 'inherit' });
    records.push({ command, args, status: 'passed', seconds: (Date.now() - started) / 1000 });
  };
  const node = (script, ...args) => run(process.execPath, [script, ...args]);
  mkdirSync(path.join(cwd, 'coverage'), { recursive: true });
  let status = 'failed';
  try {
    if (profile === 'static') {
      run('bun', ['run', 'check']);
      run('bun', ['run', 'typecheck']);
      for (const script of [
        'check:error-codes',
        'check:log-entry-schema',
        'check:conformance-vectors',
      ])
        run('bun', ['run', script]);
      node('scripts/ci/source-boundary.mjs');
      node('scripts/ci/audit.mjs');
    } else if (profile === 'unit') {
      node('scripts/check-skipped-tests.mjs');
      const executed = runSourceSuite({ cwd, run: executeCommand });
      records.push({ ...executed.command, status: 'passed' });
      node(
        'scripts/check-coverage.mjs',
        '--lcov=coverage/lcov.info',
        '--overall=80',
        '--crypto-prefix=src/internal/keymanager/',
        '--crypto-threshold=95',
        '--source-root=src',
        '--include-prefix=src/',
      );
      if (base)
        node(
          'scripts/check-diff-coverage.mjs',
          `--base=${base}`,
          '--lcov=coverage/lcov.info',
          '--include-prefix=src/',
          '--fail-under=90',
        );
    } else if (profile === 'node') {
      for (const script of ['typecheck', 'build', 'smoke:node', 'smoke:node-cjs'])
        run('bun', ['run', script]);
    } else {
      const files = expectedTestFiles(listRepoFiles(cwd), '', ['node_modules']);
      for (const [name, roots] of CONFORMANCE_SUITES) {
        const report = `coverage/conformance-${name}.xml`;
        run('bun', ['test', ...roots, '--reporter=junit', `--reporter-outfile=${report}`]);
        const expected = files.filter((file) => roots.some((root) => file.startsWith(`${root}/`)));
        const problems = checkResultFiles({
          bun: path.join(cwd, report),
          cwd,
          expectedFiles: expected,
        });
        if (problems.length) throw new Error(problems.join('\n'));
      }
    }
    status = 'passed';
  } finally {
    writeFileSync(
      path.join(cwd, 'coverage', `ci-${profile}.json`),
      `${JSON.stringify({ profile, status, diffChecked: profile === 'unit' && Boolean(base), records }, null, 2)}\n`,
    );
  }
}
if (isMainModule(import.meta.url)) {
  const options = {};
  for (const arg of process.argv.slice(2)) {
    const match = /^--(profile|base)=(.+)$/.exec(arg);
    if (!match || Object.hasOwn(options, match[1]))
      throw new Error('usage: --profile=<static|unit|conformance|node> [--base=<SHA>]');
    options[match[1]] = match[2];
  }
  runProfile(options.profile, { base: options.base });
}
