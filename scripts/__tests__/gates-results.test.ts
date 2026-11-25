import { afterAll, describe, expect, test } from 'bun:test';
import { fixture, junit } from './gates-fixture';

const f = fixture();
afterAll(() => f.close());
for (const name of ['src/a.test.ts', 'src/b.test.ts'])
  f.write(name, "import {test} from 'bun:test'; test('runs', () => {});\n");
f.commit();
const cli = () => f.cli('test-results', ['--bun=coverage/junit.xml']);
describe('SDK complete Bun result gate', () => {
  test('accepts all files and rejects actual one-file omission', () => {
    f.write('coverage/junit.xml', junit(['src/a.test.ts', 'src/b.test.ts']));
    expect(cli().status).toBe(0);
    f.write('coverage/junit.xml', junit(['src/a.test.ts']));
    const result = cli();
    expect(result.status).toBe(1);
    expect(result.output).toContain('src/b.test.ts');
  });
  test('validates the whole XML document and ignores comment/CDATA tags', () => {
    const valid = junit(['src/a.test.ts', 'src/b.test.ts']);
    for (const xml of [
      valid.slice(0, -13),
      valid.replace('</testcase>', '</testsuite>'),
      valid.replace('</testsuites>', ''),
      `${valid}<testsuites tests="0"/>`,
      '<testsuites tests="1"><testsuite file="src/a.test.ts"><testcase file="src/a.test.ts" name="x">',
      `<!DOCTYPE testsuites [<!ENTITY remote SYSTEM "file:///never-read">]>${valid}`,
      valid.replace('tests="2"', ''),
      valid.replace('tests="2"', 'tests="NaN"'),
      valid.replace('<testcase ', '<testcase><testcase '),
      valid.replace('<testcase ', '<unexpected><testcase '),
      valid.replace('</testsuites>', '<!--unterminated</testsuites>'),
      valid.replace('</testsuites>', '<![CDATA[unterminated</testsuites>'),
    ]) {
      f.write('coverage/junit.xml', xml);
      expect(cli().status).toBe(1);
    }
    const inert =
      `<!-- <testcase file="foreign.test.ts" name="fake"/> -->` +
      `<![CDATA[<testcase file="foreign.test.ts" name="fake"/><!DOCTYPE inert>]]>`;
    f.write(
      'coverage/junit.xml',
      valid
        .replace('</testcase>', `<system-out>${inert}</system-out></testcase>`)
        .replaceAll('"', "'"),
    );
    expect(cli().status).toBe(0);
    f.write(
      'coverage/junit.xml',
      '<testsuites tests="2"><!-- <testcase file="src/a.test.ts" name="fake"/> --><testsuite file="src/b.test.ts"><testcase name="real"/></testsuite></testsuites>',
    );
    expect(cli().status).toBe(1);
  });
  test('accepts actual Bun JUnit output with escaped attributes', () => {
    f.write('src/a.test.ts', `import {test} from 'bun:test'; test('quotes "&<>', () => {});`);
    const run = f.run('bun', [
      'test',
      './src/a.test.ts',
      './src/b.test.ts',
      '--reporter=junit',
      '--reporter-outfile=coverage/junit.xml',
    ]);
    expect(run.status).toBe(0);
    expect(cli().status).toBe(0);
    expect(f.read('coverage/junit.xml')).toContain('&quot;&amp;&lt;&gt;');
  });
  test('rejects runtime skip/todo/failure and zero results', () => {
    for (const status of ['<skipped/>', '<skipped message="TODO"/>', '<failure/>', '<error/>']) {
      f.write('coverage/junit.xml', junit(['src/a.test.ts', 'src/b.test.ts'], status));
      expect(cli().status).toBe(1);
    }
    for (const text of [
      '<testsuites tests="0"></testsuites>',
      'invalid',
      junit(['src/a.test.ts']).replace('tests="1"', 'tests="10"'),
    ]) {
      f.write('coverage/junit.xml', text);
      expect(cli().status).toBe(1);
    }
    expect(f.cli('test-results', ['--bun=missing.xml']).status).toBe(1);
  });
});
