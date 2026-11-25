import { afterAll, describe, expect, test } from 'bun:test';
import { fixture, lcov } from './gates-fixture';

const f = fixture();
afterAll(() => f.close());
const base = f.git('rev-parse', 'HEAD');
f.write(
  'src/value.ts',
  `${Array.from({ length: 10 }, (_, i) => `export const value${i} = ${i};`).join('\n')}\n`,
);
f.commit();
const args = [
  '--lcov=coverage/lcov.info',
  `--base=${base}`,
  '--include-prefix=src/',
  '--fail-under=90',
];
describe('SDK diff real CLI', () => {
  test('accepts90 and rejects80 despite binary attributes and display config', () => {
    f.write('.gitattributes', 'src/*.ts -diff\n');
    f.commit();
    f.git('config', 'diff.external', 'false');
    f.git('config', 'diff.relative', 'true');
    f.git('config', 'color.ui', 'always');
    f.git('config', 'diff.noprefix', 'true');
    f.write('coverage/lcov.info', lcov(`${f.root}/src/value.ts`, 9, 10));
    expect(f.cli('diff-coverage', args).status).toBe(0);
    f.git('tag', 'safe-base', base);
    expect(
      f.cli(
        'diff-coverage',
        args.map((arg) => (arg.startsWith('--base=') ? '--base=safe-base' : arg)),
      ).status,
    ).toBe(0);
    f.write('coverage/lcov.info', lcov('src/value.ts', 8, 10));
    expect(f.cli('diff-coverage', args).status).toBe(1);
  });
  test('ignores an actual failing textconv driver while retaining the coverage decision', () => {
    f.write('.gitattributes', 'src/*.ts diff=sdk-failing\n');
    f.commit();
    f.git('config', 'diff.sdk-failing.textconv', 'false');
    const control = f.run('git', ['diff', '--no-ext-diff', '--text', `${base}...HEAD`, '--', '.']);
    expect(control.status).not.toBe(0);
    f.write('coverage/lcov.info', lcov('src/value.ts', 9, 10));
    expect(f.cli('diff-coverage', args).status).toBe(0);
    f.write('coverage/lcov.info', lcov('src/value.ts', 8, 10));
    expect(f.cli('diff-coverage', args).status).toBe(1);
  });
  test('rejects option/unknown base and foreign-only coverage', () => {
    for (const value of ['--help', '--output=outside.txt', 'unknown-ref', 'HEAD^{tree}'])
      expect(
        f.cli(
          'diff-coverage',
          args.map((arg) => (arg.startsWith('--base=') ? `--base=${value}` : arg)),
        ).status,
      ).toBe(1);
    f.write('coverage/lcov.info', lcov('/foreign/src/value.ts', 10, 10));
    expect(f.cli('diff-coverage', args).status).toBe(1);
  });
  test('counts unmeasured executable source and rejects value-exporting tests', () => {
    f.write('src/new.ts', 'export const uncovered=1;\n');
    f.commit();
    f.write('coverage/lcov.info', lcov('src/value.ts', 9, 10));
    expect(f.cli('diff-coverage', args).status).toBe(1);
    f.write(
      'src/hidden.test.ts',
      "import {test} from 'bun:test'; export const hidden=1; test('x',()=>{});\n",
    );
    f.commit();
    expect(f.cli('diff-coverage', args).output).toContain('export');
  });
});
