import { afterAll, describe, expect, test } from 'bun:test';
import { symlinkSync } from 'node:fs';
import path from 'node:path';
import { fixture, lcov } from './gates-fixture';

const f = fixture();
afterAll(() => f.close());
const args = [
  '--lcov=coverage/lcov.info',
  '--overall=80',
  '--crypto-prefix=src/internal/keymanager/',
  '--crypto-threshold=95',
  '--source-root=src',
  '--include-prefix=src/',
];
f.write('src/internal/keymanager/core.ts', 'export const key = 1;\n');
f.write('src/common.ts', 'export const value = 1;\n');
f.commit();
describe('SDK coverage CLI in its own checkout', () => {
  test('keeps80/95 boundaries and excludes foreign/vendor same suffix', () => {
    f.write(
      'coverage/lcov.info',
      lcov('src/internal/keymanager/core.ts', 95) +
        lcov('src/common.ts', 80) +
        lcov('/producer/src/common.ts', 0) +
        lcov('src/../vendor/other.ts', 0),
    );
    const result = f.cli('coverage', args);
    expect(result.status).toBe(0);
    expect(result.output).toContain('175/200');
  });
  test('accepts actual realpath and temp-directory aliases without suffix matching', () => {
    const alias = path.join(f.parent, 'arbitrary-alias');
    symlinkSync(f.root, alias, 'dir');
    for (const root of [f.root, alias]) {
      f.write(
        'coverage/lcov.info',
        lcov(`${root}/src/internal/keymanager/core.ts`, 95) + lcov(`${root}/src/common.ts`, 80),
      );
      expect(f.cli('coverage', args).status).toBe(0);
    }
  });
  test('crypto below95 cannot hide in overall success', () => {
    f.write(
      'coverage/lcov.info',
      lcov('src/internal/keymanager/core.ts', 94) + lcov('src/common.ts', 100),
    );
    expect(f.cli('coverage', args).status).toBe(1);
  });
  test('overall below80 fails with crypto success', () => {
    f.write(
      'coverage/lcov.info',
      lcov('src/internal/keymanager/core.ts', 95) + lcov('src/common.ts', 60),
    );
    expect(f.cli('coverage', args).status).toBe(1);
  });
  test('missing crypto source is counted as uncovered', () => {
    f.write('coverage/lcov.info', lcov('src/common.ts', 100));
    const result = f.cli('coverage', args);
    expect(result.status).toBe(1);
    expect(result.output).toContain('src/internal/keymanager/core.ts');
  });
  test('foreign-only, empty, zero-line and invalid arguments fail', () => {
    for (const text of [
      '',
      'SF:src/common.ts\nend_of_record\n',
      lcov('/elsewhere/src/common.ts', 100),
    ]) {
      f.write('coverage/lcov.info', text);
      expect(f.cli('coverage', args).status).toBe(1);
    }
    expect(f.cli('coverage', ['--overall=NaN']).status).toBe(1);
  });
});
