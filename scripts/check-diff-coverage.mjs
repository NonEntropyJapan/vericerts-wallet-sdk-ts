#!/usr/bin/env node
import { readFileSync } from 'node:fs';
import { parsePercentArg } from './lib/cli-number.mjs';
import { createSourcePathNormalizer } from './lib/coverage-gate/source-path.mjs';
import {
  isCountedPath,
  isUncoveredSourceCandidate,
  testFileExports,
} from './lib/diff-coverage/candidate.mjs';
import { unquoteGitPath } from './lib/git-path.mjs';
import { isMainModule } from './lib/is-main-module.mjs';
import { git, gitPrefix } from './lib/repo-files.mjs';

const DEFAULT_INCLUDE_PREFIX = 'src/';
function parseArgs(argv) {
  const args = { root: null, includePrefix: DEFAULT_INCLUDE_PREFIX };
  for (const raw of argv) {
    const eq = raw.indexOf('=');
    if (!raw.startsWith('--') || eq === -1) {
      throw new Error(`unrecognized argument: ${raw}`);
    }
    const key = raw.slice(2, eq);
    const value = raw.slice(eq + 1);
    if (key === 'lcov') args.lcov = value;
    else if (key === 'base') args.base = value;
    else if (key === 'fail-under') args.failUnder = parsePercentArg('--fail-under=<0-100>', value);
    else if (key === 'root') args.root = value;
    else if (key === 'include-prefix') args.includePrefix = value;
    else throw new Error(`unknown flag: --${key}`);
  }
  if (!args.includePrefix) throw new Error('--include-prefix=<dir/> must not be empty');
  if (!args.lcov) throw new Error('--lcov=<path> is required');
  if (!args.base) throw new Error('--base=<git ref> is required');
  if (args.base.startsWith('-')) throw new Error('--base must not be a Git option');
  if (args.failUnder == null) {
    throw new Error('--fail-under=<0-100> is required');
  }
  return args;
}
export function parseAddedLines(diffText) {
  const result = new Map();
  let currentFile = null;
  let newLineNum = null;
  let inHunk = false;
  for (const line of diffText.split('\n')) {
    if (line.startsWith('diff --git ')) {
      currentFile = null;
      newLineNum = null;
      inHunk = false;
      continue;
    }
    if (!inHunk && line.startsWith('+++ ')) {
      const p = unquoteGitPath(line.slice(4).trim());
      currentFile = p === '/dev/null' ? null : p.replace(/^b\//, '');
      continue;
    }
    if (!inHunk && line.startsWith('--- ')) {
      continue;
    }
    if (line.startsWith('@@')) {
      const m = /^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@/.exec(line);
      newLineNum = m ? Number(m[1]) : null;
      inHunk = true;
      continue;
    }
    if (!inHunk || currentFile == null || newLineNum == null) continue;
    if (line.startsWith('+')) {
      if (!result.has(currentFile)) result.set(currentFile, new Set());
      result.get(currentFile).add(newLineNum);
      newLineNum += 1;
    } else if (line.startsWith('-')) {
    } else if (line.startsWith(' ')) {
      newLineNum += 1;
    }
  }
  return result;
}
export function parseLcovLines(text) {
  const files = new Map();
  let current = null;
  for (const line of text.split('\n')) {
    if (line.startsWith('SF:')) {
      current = new Map();
      files.set(line.slice(3).trim(), current);
    } else if (line.startsWith('DA:') && current) {
      const [lineStr, hitsStr] = line.slice(3).split(',');
      current.set(Number(lineStr), Number(hitsStr));
    } else if (line.startsWith('end_of_record')) {
      current = null;
    }
  }
  return files;
}
export function normalizeLcovFiles(lcovFiles, cwd) {
  const normalize = createSourcePathNormalizer(cwd);
  return new Map([...lcovFiles].map(([file, lines]) => [normalize(file), lines]));
}
function isCodeLine(text) {
  const t = text.trim();
  if (t === '') return false;
  if (/^(?:\/\/|\/\*|\*|<!--)/.test(t)) return false;
  return !/^[{}()[\];,]+$/.test(t);
}
export function computeDiffCoverage(
  addedLines,
  lcovFiles,
  root,
  readSource = null,
  includePrefix = DEFAULT_INCLUDE_PREFIX,
) {
  let found = 0;
  let hit = 0;
  const uncovered = [];
  const exportingTests = [];
  const prefix = root ? `${root}/` : '';
  for (const [file, lines] of addedLines) {
    if (root && !file.startsWith(prefix)) continue;
    const key = root ? file.slice(prefix.length) : file;
    if (!key.startsWith(includePrefix)) continue;
    if (readSource && testFileExports(file, readSource(file)?.join('\n')))
      exportingTests.push(file);
    if (!isCountedPath(file)) continue;
    const lineHits = lcovFiles.get(key);
    const sortedLines = [...lines].sort((a, b) => a - b);
    if (!lineHits) {
      const source = readSource ? readSource(file) : null;
      if (!source || !isUncoveredSourceCandidate(file, source.join('\n'))) continue;
      for (const lineNum of sortedLines) {
        if (!isCodeLine(source[lineNum - 1] ?? '')) continue;
        found += 1;
        uncovered.push(`${file}:${lineNum}`);
      }
      continue;
    }
    for (const lineNum of sortedLines) {
      if (!lineHits.has(lineNum)) continue;
      found += 1;
      if (lineHits.get(lineNum) > 0) {
        hit += 1;
      } else {
        uncovered.push(`${file}:${lineNum}`);
      }
    }
  }
  return { found, hit, uncovered, exportingTests, pct: found === 0 ? null : (hit / found) * 100 };
}
function readSourceAtHead(file) {
  return git(process.cwd(), ['show', `HEAD:${file}`]).split('\n');
}
function main() {
  const args = parseArgs(process.argv.slice(2));
  const prefix = gitPrefix(process.cwd());
  if (args.root !== null && args.root !== prefix)
    throw new Error('--root must match the cwd Git prefix');
  args.root = prefix;
  const base = git(process.cwd(), [
    'rev-parse',
    '--verify',
    '--end-of-options',
    `${args.base}^{commit}`,
  ]).trim();
  if (!/^[a-f0-9]{40}$/.test(base)) throw new Error('Git base did not resolve to a commit');
  const diffText = git(process.cwd(), [
    'diff',
    '--text',
    '--no-ext-diff',
    '--no-textconv',
    '--no-color',
    '--no-relative',
    '--src-prefix=a/',
    '--dst-prefix=b/',
    '--unified=0',
    `${base}...HEAD`,
    '--',
    '.',
  ]);
  const addedLines = parseAddedLines(diffText);
  const lcovFiles = normalizeLcovFiles(
    parseLcovLines(readFileSync(args.lcov, 'utf8')),
    process.cwd(),
  );
  const result = computeDiffCoverage(
    addedLines,
    lcovFiles,
    args.root,
    readSourceAtHead,
    args.includePrefix,
  );
  if (result.exportingTests.length > 0) {
    console.error(
      'FAIL: テストファイルが値 (関数・クラス・定数) を export している。テストの lcov はテストファイルを計測しないので、' +
        '本番ロジックが差分カバレッジに現れない。本番コードはテストの無いモジュールへ移す:',
    );
    for (const file of result.exportingTests) console.error(`  - ${file}`);
    process.exit(1);
  }
  if (result.found === 0) {
    console.log('Diff coverage: no instrumented added lines in this diff (nothing to check)');
    return;
  }
  console.log(
    `Diff coverage: ${result.hit}/${result.found} (${result.pct.toFixed(2)}%), threshold ${args.failUnder}%`,
  );
  if (result.pct < args.failUnder) {
    console.error(
      `FAIL: diff coverage ${result.pct.toFixed(2)}% is below threshold ${args.failUnder}%`,
    );
    console.error(`Uncovered added lines:\n${result.uncovered.join('\n')}`);
    process.exit(1);
  }
}
if (isMainModule(import.meta.url)) {
  main();
}
