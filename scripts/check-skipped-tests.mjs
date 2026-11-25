#!/usr/bin/env node
import path from 'node:path';
import { isMainModule } from './lib/is-main-module.mjs';
import { SKIP_ALLOWANCE } from './lib/skipped-tests/allowance.mjs';
import { listTestFiles } from './lib/skipped-tests/files.mjs';
import { findDisabledInFile } from './lib/skipped-tests/scan.mjs';

const HOW_TO_ALLOW =
  '環境依存で本当に走らせられないテストなら scripts/lib/skipped-tests/allowance.mjs の SKIP_ALLOWANCE に ' +
  "{ '<ファイル>': [{ form: '<形>', condition: '<条件式>', reason: '<理由>' }] } を足す。それ以外は skip を外してテストを直す";
const describe = (form, condition) =>
  `\`${form}\`${condition === '' ? '' : ` (条件 \`${condition}\`)`}`;
export function checkSkippedTests(root = '.', allowance = SKIP_ALLOWANCE) {
  const problems = [];
  const files = listTestFiles(root);
  if (files.length === 0) return ['No SDK test files found'];
  const actual = new Map();
  for (const file of files) {
    for (const hit of findDisabledInFile(path.join(root, file))) {
      const key = `${file}\0${hit.form}\0${hit.condition}`;
      actual.set(key, [...(actual.get(key) ?? []), hit.line]);
    }
  }
  const allowed = new Map();
  for (const [file, entries] of Object.entries(allowance)) {
    for (const entry of entries) {
      const { form, condition = '', count = 1, reason } = entry;
      if (
        typeof reason !== 'string' ||
        reason.trim() === '' ||
        !Number.isInteger(count) ||
        count < 1
      ) {
        problems.push(
          `${file}: 許可 ${describe(form, condition)} に理由 (reason) か件数 (count) が無い`,
        );
        continue;
      }
      const key = `${file}\0${form}\0${condition}`;
      allowed.set(key, (allowed.get(key) ?? 0) + count);
    }
  }
  for (const [key, lines] of actual) {
    const [file, form, condition] = key.split('\0');
    const allowedCount = allowed.get(key) ?? 0;
    if (lines.length > allowedCount) {
      const otherConditions = [...allowed.keys()]
        .filter((other) => other.startsWith(`${file}\0${form}\0`))
        .map((other) => other.split('\0')[2]);
      const hint =
        otherConditions.length > 0 && allowedCount === 0
          ? ` 許可済みの条件 (${otherConditions.map((c) => `\`${c}\``).join(', ')}) と違う`
          : '';
      problems.push(
        `${file}:${lines[allowedCount]}: テストを無効化する形 ${describe(form, condition)} が ${lines.length} 件ある (許可 ${allowedCount} 件, 行 ${lines.join(', ')})。${hint}${HOW_TO_ALLOW}`,
      );
    }
  }
  for (const [key, count] of allowed) {
    const [file, form, condition] = key.split('\0');
    if ((actual.get(key)?.length ?? 0) < count) {
      problems.push(
        `${file}: 許可 ${describe(form, condition)} (${count} 件) が実体より多い (skip が減った / 条件が変わった / ファイルが消えた)。allowance.mjs から外す`,
      );
    }
  }
  return problems;
}
function main() {
  const rootArg = process.argv.find((arg) => arg.startsWith('--root='));
  const root = rootArg === undefined ? '.' : rootArg.slice('--root='.length);
  const problems = checkSkippedTests(root);
  if (problems.length > 0) {
    console.error('テストの無効化 (skip / only / todo / fixme) が見つかった:');
    for (const problem of problems) console.error(`  - ${problem}`);
    process.exit(1);
  }
  console.log(`check-skipped-tests: OK (${listTestFiles(root).length} files scanned)`);
}
if (isMainModule(import.meta.url)) main();
