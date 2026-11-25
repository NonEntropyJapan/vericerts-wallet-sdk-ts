import { expect, test } from 'bun:test';
import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { verifyInteropCases } from '../ci/interop/case-contract.mjs';
import { interopGroups } from '../ci/interop/groups.mjs';
import reportNodeEvents from '../ci/interop/node-reporter.mjs';
import { readInteropGroup } from '../ci/interop/reports.mjs';

const consumer = '/isolated/consumer';
const bunGroup = interopGroups.find(({ id }) => id === '03-adapter-kid');
const nodeGroup = interopGroups.find(({ id }) => id === '04-real-veramo-kid');
const fixture = (group, content) => {
  const root = mkdtempSync(path.join(tmpdir(), 'sdk-interop-reporter-'));
  try {
    const request = { group, consumer };
    for (const [name, text] of Object.entries(content)) {
      request[name] = path.join(root, name);
      writeFileSync(request[name], text);
    }
    return readInteropGroup(request);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
};

function bunXml(cases, target = bunGroup.targets[0]) {
  return `<?xml version="1.0"?>
<testsuites tests="${cases.length}">
  <testsuite tests="${cases.length}" file="${consumer}/${target}">
    ${cases.join('\n')}
  </testsuite>
</testsuites>`;
}

test('Bun report identifies distinct classes and normalizes the exact group file', () => {
  const junit = bunXml([
    '<testcase name="same &amp; name" classname="a"/>',
    '<testcase name="same &amp; name" classname="b"/>',
  ]);
  const report = fixture(bunGroup, { junit });
  expect(report.files).toEqual(bunGroup.targets);
  expect(report.declaredTests).toBe(2);
  expect(report.cases.map(({ name, classname, status }) => [name, classname, status])).toEqual([
    ['same & name', 'a', 'passed'],
    ['same & name', 'b', 'passed'],
  ]);
});

test('Bun report rejects zero, partial, duplicate and non-passing cases', () => {
  const pass = '<testcase name="case" classname="a"/>';
  for (const junit of [
    bunXml([]),
    bunXml([pass], 'test/interop/extra.mjs'),
    bunXml([pass, pass]),
    bunXml(['<testcase name="case"><skipped/></testcase>']),
    bunXml(['<testcase name="case"><skipped message="TODO"/></testcase>']),
    bunXml(['<testcase name="case"><failure/></testcase>']),
    bunXml([pass]).replace('tests="1"', 'tests="2"'),
    bunXml([pass]).replace('</testsuites>', ''),
  ]) {
    expect(() => fixture(bunGroup, { junit })).toThrow();
  }
});

const nodeFile = path.join(consumer, nodeGroup.targets[0]);
const leaf = {
  type: 'test:pass',
  data: {
    details: { type: 'test', classname: 'suite' },
    name: 'leaf',
    file: nodeFile,
    nesting: 1,
    line: 10,
  },
};
const suite = {
  type: 'test:pass',
  data: { details: { type: 'suite' }, name: 'suite', file: nodeFile, nesting: 0 },
};
const complete = { type: 'test:complete', data: { ...leaf.data } };
const counts = {
  tests: 1,
  suites: 1,
  topLevel: 1,
  passed: 1,
  failed: 0,
  cancelled: 0,
  skipped: 0,
  todo: 0,
};
const perFile = { type: 'test:summary', data: { success: true, file: nodeFile, counts } };
const global = { type: 'test:summary', data: { success: true, counts } };
const jsonl = (events) => events.map((event) => `${JSON.stringify(event)}\n`).join('');
const nativeTap = `TAP version 13
# Subtest: suite
    # Subtest: leaf
    ok 1 - leaf
    1..1
ok 1 - suite
1..1
# tests 1
# suites 1
# pass 1
# fail 0
# cancelled 0
# skipped 0
# todo 0
# duration_ms 1.1
`;

test('Node reports count only final leaf events and verify both summaries and native TAP', () => {
  const report = fixture(nodeGroup, {
    events: jsonl([complete, leaf, suite, perFile, global]),
    tap: nativeTap,
  });
  expect(report).toEqual({
    files: nodeGroup.targets,
    declaredTests: 1,
    cases: [
      {
        file: nodeGroup.targets[0],
        classname: 'suite',
        name: 'leaf',
        runtime: 'node',
        status: 'passed',
        sourceLine: 10,
      },
    ],
  });
});

test('Node reports reject missing, repeated or conflicting evidence', () => {
  const good = jsonl([leaf, suite, perFile, global]);
  for (const events of [
    jsonl([leaf, suite, global]),
    jsonl([leaf, suite, perFile]),
    jsonl([leaf, leaf, suite, perFile, global]),
    jsonl([leaf, suite, perFile, perFile, global]),
    jsonl([{ ...leaf, data: { ...leaf.data, skip: 'not run' } }, suite, perFile, global]),
    jsonl([{ ...leaf, data: { ...leaf.data, todo: true } }, suite, perFile, global]),
    jsonl([{ ...leaf, type: 'test:fail' }, suite, perFile, global]),
    good.trimEnd(),
  ]) {
    expect(() => fixture(nodeGroup, { events, tap: nativeTap })).toThrow();
  }
  for (const tap of [
    nativeTap.replace('# tests 1', '# tests 2'),
    nativeTap.replace('ok 1 - leaf', 'ok 1 - leaf # SKIP omitted'),
    nativeTap.replace('ok 1 - leaf', 'not ok 1 - leaf'),
    nativeTap.replace('    ok 1 - leaf\n', ''),
  ]) {
    expect(() => fixture(nodeGroup, { events: good, tap })).toThrow();
  }
});

test('Node event reporter preserves diagnostic data and terminates each JSON line', async () => {
  const error = new Error('diagnostic');
  error.cause = error;
  const iterator = reportNodeEvents([{ type: 'test:diagnostic', data: { error, value: 1n } }]);
  const { value } = await iterator.next();
  expect(value.endsWith('\n')).toBe(true);
  const { data } = JSON.parse(value);
  expect(data.error.message).toBe('diagnostic');
  expect(data.error.cause).toBe('[Circular]');
  expect(data.value).toBe('1');
  expect((await iterator.next()).done).toBe(true);
});

test('public contract covers the original 235 identities and nine independent additions', () => {
  const sha256 = (data) => createHash('sha256').update(data).digest('hex');
  const rows = (scope, runtime) =>
    Object.entries(scope).flatMap(([file, classes]) =>
      Object.entries(classes).flatMap(([classname, names]) =>
        names.map((name) => ({
          file,
          classname,
          name,
          runtime,
          status: 'passed',
        })),
      ),
    );
  const inputs = [];
  const cases = [];
  for (const [runtime, originalCount, additionalCount, renameCount] of [
    ['bun', 100, 2, 1],
    ['node', 135, 7, 2],
  ]) {
    const path = `test/interop/contracts/public-cases-${runtime}.json`;
    const bytes = readFileSync(new URL(`../../${path}`, import.meta.url));
    const contract = JSON.parse(bytes);
    expect(contract.runtime).toBe(runtime);
    const original = rows(contract.originalCases, runtime);
    const additions = rows(contract.additionalCases, runtime);
    expect(original).toHaveLength(originalCount);
    expect(additions).toHaveLength(additionalCount);
    expect(contract.renamedCases).toHaveLength(renameCount);
    inputs.push({ path, sha256: sha256(bytes) });
    cases.push(...original, ...additions);
  }
  expect(verifyInteropCases(cases)).toEqual({
    contractSha256: sha256(JSON.stringify(inputs)),
    missing: 0,
    duplicate: 0,
    unexpected: 0,
    allowedRenames: 3,
  });
  expect(() => verifyInteropCases(cases.slice(1))).toThrow(/Missing 1/);
  expect(() => verifyInteropCases([...cases, cases[0]])).toThrow(/Duplicate/);
  expect(() =>
    verifyInteropCases([{ ...cases[0], classname: 'new suite' }, ...cases.slice(1)]),
  ).toThrow(/Unexpected/);
  expect(() => verifyInteropCases([{ ...cases[0], status: 'skipped' }, ...cases.slice(1)])).toThrow(
    /passed/,
  );
});
