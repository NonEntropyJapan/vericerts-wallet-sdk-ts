import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { parseBunJunit } from '../../lib/result-gate/parse.mjs';
import { interopCaseKey } from './case-contract.mjs';
import { interopGroups } from './groups.mjs';

const countKeys = [
  'topLevel',
  'tests',
  'suites',
  'passed',
  'failed',
  'cancelled',
  'skipped',
  'todo',
];
const read = (file) => readFileSync(file, 'utf8');
const isName = (value) => typeof value === 'string' && value.length > 0;

function requireExpectedFiles(expected, actual) {
  assert.deepEqual(
    [...actual].sort(),
    [...expected].sort(),
    'Interop report files differ from group',
  );
}

function readBunReport(xml, normalizeFile) {
  const report = parseBunJunit(xml);
  return {
    files: new Set([...report.files].map(normalizeFile)),
    cases: report.cases.map((row) => ({
      ...row,
      file: normalizeFile(row.file),
      classname: row.classname ?? '',
      runtime: 'bun',
    })),
    declaredTests: report.declaredTests,
  };
}

const tapFooter =
  /\n1\.\.(\d+)\n# tests (\d+)\n# suites (\d+)\n# pass (\d+)\n# fail (\d+)\n# cancelled (\d+)\n# skipped (\d+)\n# todo (\d+)\n# duration_ms \d+(?:\.\d+)?\n?$/;

function assertTapAgreement(tap, counts) {
  const text = tap.replaceAll('\r\n', '\n');
  assert.ok(text.startsWith('TAP version 13\n'), 'Missing native Node TAP header');
  assert.doesNotMatch(
    text,
    /^\s*(?:not ok\b|Bail out!)|^[ \t]*ok \d+ .*?(?<!\\)# (?:SKIP|TODO)(?:\s|$)/im,
    'Native Node TAP contains a non-passing result',
  );
  const footer = tapFooter.exec(text);
  assert.ok(footer, 'Missing complete native Node TAP summary');
  assert.deepEqual(
    footer.slice(1).map(Number),
    countKeys.map((key) => counts[key]),
    'Native Node TAP summary differs from JSONL',
  );
  assert.equal(
    [...text.matchAll(/^[ \t]*ok \d+ - /gm)].length,
    counts.tests + counts.suites,
    'Native Node TAP result count differs from JSONL',
  );
  assert.equal(
    [...text.matchAll(/^ok \d+ - /gm)].length,
    counts.topLevel,
    'Native Node TAP top-level result count differs from JSONL',
  );
}

function assertNodeSummary(data, totals, source) {
  const { counts, success } = data;
  assert.equal(success, true, `Node JSONL reports failure: ${source}`);
  assert.ok(counts && typeof counts === 'object', `Missing Node JSONL summary counts: ${source}`);
  const expected = {
    ...totals,
    passed: totals.tests,
    failed: 0,
    cancelled: 0,
    skipped: 0,
    todo: 0,
  };
  for (const key of countKeys) {
    assert.equal(counts[key], expected[key], `Mismatched Node JSONL count ${key}: ${source}`);
  }
}

function readNodeReport(events, tap, normalizeFile, targets) {
  const lines = events.split(/\r?\n/);
  assert.ok(lines.pop() === '' && lines.length > 0, 'Incomplete Node JSONL event stream');
  const perFile = new Map(targets.map((file) => [file, { tests: 0, suites: 0, topLevel: 0 }]));
  const summaries = new Map();
  const cases = [];
  let global;

  for (const line of lines) {
    const { type, data } = JSON.parse(line);
    assert.ok(isName(type) && data && typeof data === 'object', 'Malformed Node JSONL event');
    assert.equal(global, undefined, 'Unexpected Node JSONL event after global summary');
    if (type === 'test:summary') {
      if (data.file === undefined) global = data;
      else {
        const file = normalizeFile(data.file);
        assert.ok(!summaries.has(file), `Duplicate Node JSONL file summary: ${file}`);
        summaries.set(file, data);
      }
      continue;
    }
    if (type !== 'test:pass' && type !== 'test:fail') continue;

    const { details, name, nesting, line: sourceLine, skip, todo } = data;
    assert.ok(
      type === 'test:pass' &&
        [undefined, false].includes(skip) &&
        [undefined, false].includes(todo),
      `Non-passing Node JSONL result: ${name}`,
    );
    assert.ok(isName(name) && Number.isSafeInteger(nesting) && nesting >= 0);
    const file = normalizeFile(data.file);
    assert.ok(!summaries.has(file), `Node JSONL result after file summary: ${file}`);
    const totals = perFile.get(file);
    if (nesting === 0) totals.topLevel++;
    if (details?.type === 'suite') {
      totals.suites++;
    } else {
      assert.equal(details?.type, 'test', `Unknown Node JSONL result type: ${name}`);
      totals.tests++;
      cases.push({
        file,
        classname: data.classname ?? details.classname ?? '',
        name,
        runtime: 'node',
        status: 'passed',
        ...(Number.isSafeInteger(sourceLine) && sourceLine > 0 ? { sourceLine } : {}),
      });
    }
  }

  assert.ok(global, 'Missing global Node JSONL summary');
  requireExpectedFiles(targets, summaries.keys());
  const totals = { tests: 0, suites: 0, topLevel: 0 };
  for (const [file, counts] of perFile) {
    assertNodeSummary(summaries.get(file), counts, file);
    totals.tests += counts.tests;
    totals.suites += counts.suites;
    totals.topLevel += counts.topLevel;
  }
  assertNodeSummary(global, totals, 'global');
  assertTapAgreement(tap, global.counts);
  return { files: new Set(summaries.keys()), cases, declaredTests: global.counts.tests };
}

export function readInteropGroup({ group, consumer, junit, events, tap }) {
  assert.deepEqual(
    group,
    interopGroups.find(({ id }) => id === group.id),
    'Unknown Interop group',
  );
  assert.ok(path.isAbsolute(consumer), 'Interop consumer path must be absolute');
  const targets = new Set(group.targets);
  const normalizeFile = (reported) => {
    assert.ok(isName(reported) && !/[\\\r\n]/.test(reported), 'Invalid Interop result file');
    const file = path
      .relative(consumer, path.resolve(consumer, reported))
      .split(path.sep)
      .join('/');
    assert.ok(targets.has(file), `Unexpected Interop result file: ${reported}`);
    return file;
  };
  assert.ok(
    group.runtime === 'bun' ? junit && !events && !tap : !junit && events && tap,
    'Missing or conflicting Interop reports',
  );
  const report =
    group.runtime === 'bun'
      ? readBunReport(read(junit), normalizeFile)
      : readNodeReport(read(events), read(tap), normalizeFile, group.targets);
  requireExpectedFiles(targets, report.files);
  requireExpectedFiles(targets, new Set(report.cases.map(({ file }) => file)));
  assert.ok(report.declaredTests > 0, 'Interop report contains zero leaf cases');
  assert.equal(report.declaredTests, report.cases.length, 'Interop leaf case count mismatch');

  const seen = new Set();
  for (const row of report.cases) {
    assert.ok(
      isName(row.name) && typeof row.classname === 'string',
      'Invalid Interop case identity',
    );
    assert.equal(row.status, 'passed', `Interop case did not pass: ${row.name}`);
    const key = interopCaseKey(row);
    assert.ok(!seen.has(key), `Duplicate Interop case: ${key}`);
    seen.add(key);
  }
  return { ...report, files: [...report.files].sort() };
}
