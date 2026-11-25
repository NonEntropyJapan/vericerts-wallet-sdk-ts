import { afterAll, describe, expect, test } from 'bun:test';
import { writeFileSync } from 'node:fs';
import path from 'node:path';
import { cleanEnvironment, execute } from '../ci/environment.mjs';
import { CONFORMANCE_SUITES, runProfile } from '../ci/run.mjs';
import { runSourceSuite } from '../ci/source-suite.mjs';
import { currentSuiteManifest } from '../ci/suite-manifest.mjs';
import { fixture, junit } from './gates-fixture';

const f = fixture();
afterAll(() => f.close());
f.write('src/core.test.ts', "import {test} from 'bun:test'; test('runs',()=>{});\n");
f.commit();
describe('SDK CI profile contracts', () => {
  test('unit fixes80/95/90 and runs every source file', () => {
    const commands: string[][] = [];
    runProfile('unit', {
      cwd: f.root,
      base: 'a'.repeat(40),
      executeCommand: (command, args) => {
        commands.push([command, ...args]);
        if (command === 'bun')
          writeFileSync(path.join(f.root, 'coverage/junit.xml'), junit(['src/core.test.ts']));
        return '';
      },
    });
    expect(commands.find((args) => args.includes('scripts/check-coverage.mjs'))).toEqual(
      expect.arrayContaining([
        '--overall=80',
        '--crypto-threshold=95',
        '--source-root=src',
        '--include-prefix=src/',
      ]),
    );
    expect(commands.find((args) => args.includes('scripts/check-diff-coverage.mjs'))).toEqual(
      expect.arrayContaining(['--fail-under=90', `--base=${'a'.repeat(40)}`]),
    );
    expect(commands.find((args) => args[0] === 'bun')).toEqual(
      expect.arrayContaining(['./src/core.test.ts', '--coverage', '--reporter=junit']),
    );
    expect(commands.some((args) => args.includes('scripts/check-skipped-tests.mjs'))).toBe(true);
  });
  test('normal SDK runner can share source/package manifest without running Interop in source coverage', () => {
    const isolated = fixture();
    try {
      isolated.write('src/core.test.ts', "import {test} from 'bun:test'; test('runs',()=>{});\n");
      isolated.write(
        'test/interop/package.test.mjs',
        "import {test} from 'node:test'; test('runs',()=>{});\n",
      );
      isolated.commit();
      const manifest = currentSuiteManifest(isolated.root);
      let args: string[] = [];
      const result = runSourceSuite({
        cwd: isolated.root,
        manifest,
        run: (_command, input) => {
          args = input;
          writeFileSync(
            path.join(isolated.root, 'coverage/junit.xml'),
            junit(['src/core.test.ts']),
          );
          return '';
        },
      });
      expect(args).toContain('./src/core.test.ts');
      expect(args).not.toContain('./test/interop/package.test.mjs');
      expect(result.fragment.source).toEqual(manifest.source);
      expect(result.manifest.files).toHaveLength(2);
      isolated.write('src/core.test.ts', '// dirty\n');
      expect(() => runSourceSuite({ cwd: isolated.root, manifest })).toThrow('clean projection');
    } finally {
      isolated.close();
    }
  });
  test('static and Node profiles keep their independent source contracts', () => {
    for (const profile of ['static', 'node']) {
      const commands: string[][] = [];
      runProfile(profile, {
        cwd: f.root,
        executeCommand: (command, args) => {
          commands.push([command, ...args]);
          return '';
        },
      });
      for (const required of profile === 'static'
        ? [
            'check',
            'typecheck',
            'check:error-codes',
            'check:log-entry-schema',
            'check:conformance-vectors',
          ]
        : ['typecheck', 'build', 'smoke:node', 'smoke:node-cjs'])
        expect(commands.some((args) => args.includes(required))).toBe(true);
      if (profile === 'static')
        for (const required of ['scripts/ci/source-boundary.mjs', 'scripts/ci/audit.mjs'])
          expect(commands.some((args) => args.includes(required))).toBe(true);
    }
    expect(() => runProfile('unknown', { cwd: f.root })).toThrow('Unknown');
  });
  test('child receives no producer/GitHub context or credentials and normalized cwd', () => {
    const vars = [
      'PWD',
      'INIT_CWD',
      'OLDPWD',
      'GITHUB_WORKSPACE',
      'SDK_SOURCE_ROOT',
      'SDK_CI_WORKSPACE',
      'GH_TOKEN',
      'GITHUB_SHA',
      'GITHUB_ENV',
      'GITHUB_TOKEN',
      'ACTIONS_RUNTIME_TOKEN',
    ];
    const before = Object.fromEntries(vars.map((key) => [key, process.env[key]]));
    try {
      for (const key of vars) process.env[key] = '/producer/private';
      const env = cleanEnvironment();
      for (const key of vars) expect(env[key]).toBeUndefined();
      const child = JSON.parse(
        execute('node', ['-e', 'console.log(JSON.stringify(process.env))'], f.root),
      );
      expect(child.PWD).toBe(f.root);
      expect(child.INIT_CWD).toBe(f.root);
      for (const key of vars.slice(2)) expect(child[key]).toBeUndefined();
    } finally {
      for (const key of vars)
        if (before[key] === undefined) delete process.env[key];
        else process.env[key] = before[key];
    }
  });
  test('all five conformance profiles execute real Bun reports and reject a skipped or empty file', () => {
    for (const [, roots] of CONFORMANCE_SUITES)
      for (const root of roots)
        f.write(`${root}/check.test.ts`, "import {test} from 'bun:test'; test('runs',()=>{});\n");
    f.commit();
    expect(() => runProfile('conformance', { cwd: f.root })).not.toThrow();
    for (const [name] of CONFORMANCE_SUITES)
      expect(f.read(`coverage/conformance-${name}.xml`)).toContain('<testsuites');
    const file = `${CONFORMANCE_SUITES[0][1][0]}/check.test.ts`;
    f.write(file, "import {test} from 'bun:test'; test.skip('skipped',()=>{});\n");
    expect(() => runProfile('conformance', { cwd: f.root })).toThrow('skip / todo');
    expect(JSON.parse(f.read('coverage/ci-conformance.json')).status).toBe('failed');
    f.write(file, 'export {};\n');
    expect(() => runProfile('conformance', { cwd: f.root })).toThrow('1 件も無い');
  });
});
