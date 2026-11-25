import { expect, test } from 'bun:test';
import { parseBunJunit } from '../../scripts/lib/result-gate/parse.mjs';

test('preserves named, numeric and literal references in JUnit identities', () => {
  const xml =
    '<testsuites tests="1"><testsuite file="src/a&#x2e;test.ts">' +
    '<testcase name="&quot;&apos;&amp;&lt;&gt;&#10;&#x1F680; &amp;#10;" ' +
    'classname="suite&#x9;next&#13;line\r\nliteral"/></testsuite></testsuites>';
  const report = parseBunJunit(xml);
  expect([...report.files]).toEqual(['src/a.test.ts']);
  expect(report.cases).toEqual([
    {
      file: 'src/a.test.ts',
      name: '"\'&<>\n\u{1F680} &#10;',
      classname: 'suite\tnext\rline literal',
      status: 'passed',
    },
  ]);
});

test('rejects malformed references and characters prohibited in XML attributes', () => {
  for (const reference of [
    '&bogus;',
    '&nbsp;',
    '&amp',
    '&#;',
    '&#x;',
    '&#x1g;',
    '&#-1;',
    '&#1114112;',
    '&#xD800;',
    '&#xFFFE;',
    '&#0;',
    '\u0001',
    '<',
  ]) {
    const xml =
      '<testsuites tests="1"><testsuite file="src/a.test.ts">' +
      `<testcase name="${reference}"/></testsuite></testsuites>`;
    expect(() => parseBunJunit(xml)).toThrow('Invalid Bun JUnit');
  }
});
