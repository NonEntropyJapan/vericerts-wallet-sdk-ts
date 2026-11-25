import { expect, test } from 'bun:test';
import { execFileSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { createLocalSnapshot, requireUnchangedInputs } from '../ci/local-snapshot.mjs';
import { createSuiteManifest, validateSuiteResults } from '../ci/suite-manifest.mjs';
import { fixture } from '../packed-consumer/artifact-fixtures.mjs';
import { readReceipt, requireReleaseChecks, saveReceipt } from '../packed-consumer/receipt.mjs';

test('a complete receipt cannot promote its development origin', () => {
  const artifact = fixture();
  try {
    expect(() => requireReleaseChecks(readReceipt(artifact.receiptPath))).not.toThrow();
    const origin = { ...artifact.receipt.source, validationOrigin: 'development-snapshot' };
    saveReceipt(artifact.receiptPath, { ...artifact.receipt, source: origin });
    expect(() => requireReleaseChecks(readReceipt(artifact.receiptPath))).toThrow('Development');
    for (const validationOrigin of [undefined, 'unknown']) {
      saveReceipt(artifact.receiptPath, {
        ...artifact.receipt,
        source: { ...origin, validationOrigin },
      });
      expect(() => readReceipt(artifact.receiptPath)).toThrow('validation origin');
    }
  } finally {
    rmSync(artifact.root, { recursive: true, force: true });
  }
});

test('requires the same origin on every file-complete suite fragment', () => {
  const source = {
    revision: 'a'.repeat(40),
    tree: 'b'.repeat(40),
    validationOrigin: 'development-snapshot',
  };
  const file = 'src/example.test.ts';
  const manifest = createSuiteManifest([file], source);
  const fragment = {
    suite: 'source',
    source,
    report: {
      files: [file],
      cases: [{ file, name: 'example', status: 'passed' }],
      declaredTests: 1,
    },
  };
  expect(validateSuiteResults(manifest, [fragment]).complete).toBe(true);
  expect(() =>
    validateSuiteResults(manifest, [
      { ...fragment, source: { ...source, validationOrigin: 'committed-projection' } },
    ]),
  ).toThrow('another SDK source');
  expect(() => createSuiteManifest([file], { ...source, validationOrigin: undefined })).toThrow(
    'validation origin',
  );
});

test('working-tree snapshot uses actual SDK bytes, includes untracked inputs, and rejects staleness', () => {
  const root = mkdtempSync(path.join(tmpdir(), 'sdk-snapshot-test-'));
  const repository = path.join(root, 'producer');
  const sdk = path.join(repository, 'sdk');
  const output = path.join(root, 'snapshot');
  const runGit = (...args: string[]) =>
    execFileSync('git', args, { cwd: repository, encoding: 'utf8' });
  try {
    mkdirSync(sdk, { recursive: true });
    mkdirSync(output);
    runGit('init', '-q');
    writeFileSync(path.join(repository, 'private.txt'), 'parent only');
    writeFileSync(path.join(sdk, 'base.txt'), 'before');
    runGit('add', '.');
    runGit(
      '-c',
      'user.name=Snapshot Test',
      '-c',
      'user.email=snapshot@example.invalid',
      '-c',
      'commit.gpgsign=false',
      'commit',
      '-qm',
      'fixture',
    );
    writeFileSync(path.join(sdk, 'base.txt'), 'after');
    writeFileSync(path.join(sdk, 'new.txt'), 'new');
    const result = createLocalSnapshot(sdk, output);
    expect(result.validationOrigin).toBe('development-snapshot');
    expect(result.originalHead).not.toBe(result.sdkProjectedSHA);
    expect(result.inputs.map((entry) => entry.path)).toEqual(['base.txt', 'new.txt']);
    expect(readFileSync(path.join(result.workspace, 'base.txt'), 'utf8')).toBe('after');
    expect(() => requireUnchangedInputs(sdk, result.inputs)).not.toThrow();
    writeFileSync(path.join(sdk, 'new.txt'), 'changed');
    expect(() => requireUnchangedInputs(sdk, result.inputs)).toThrow('inputs changed');

    const normalized = path.join(root, 'snapshot-normalized');
    mkdirSync(normalized);
    writeFileSync(path.join(sdk, '.gitattributes'), '*.txt text eol=lf\n');
    writeFileSync(path.join(sdk, 'base.txt'), 'actual\r\n');
    expect(() => createLocalSnapshot(sdk, normalized)).toThrow('exact input bytes and mode');
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
