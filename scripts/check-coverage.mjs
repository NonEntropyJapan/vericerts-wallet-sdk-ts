#!/usr/bin/env node
import { readFileSync } from 'node:fs';
import { parsePercentArg } from './lib/cli-number.mjs';
import { createSourcePathNormalizer } from './lib/coverage-gate/source-path.mjs';
import { unmeasuredRecords } from './lib/coverage-gate/unmeasured-sources.mjs';
import { isMainModule } from './lib/is-main-module.mjs';

function parseArgs(argv) {
  const args = {
    overall: null,
    cryptoPrefix: null,
    cryptoThreshold: null,
    sourceRoot: null,
    includePrefix: null,
  };
  for (const raw of argv) {
    const eq = raw.indexOf('=');
    if (!raw.startsWith('--') || eq === -1) {
      throw new Error(`unrecognized argument: ${raw}`);
    }
    const key = raw.slice(2, eq);
    const value = raw.slice(eq + 1);
    if (key === 'lcov') args.lcov = value;
    else if (key === 'overall') args.overall = parsePercentArg('--overall=<0-100>', value);
    else if (key === 'crypto-prefix') {
      if (value === '') throw new Error('--crypto-prefix must not be empty');
      args.cryptoPrefix = value;
    } else if (key === 'crypto-threshold') {
      args.cryptoThreshold = parsePercentArg('--crypto-threshold=<0-100>', value);
    } else if (key === 'source-root') {
      if (value === '') throw new Error('--source-root must not be empty');
      args.sourceRoot = value;
    } else if (key === 'include-prefix') {
      if (value === '') throw new Error('--include-prefix must not be empty');
      args.includePrefix = value;
    } else throw new Error(`unknown flag: --${key}`);
  }
  if (!args.lcov) throw new Error('--lcov=<path> is required');
  if (args.overall == null) throw new Error('--overall=<0-100> is required');
  if ((args.cryptoPrefix == null) !== (args.cryptoThreshold == null)) {
    throw new Error('--crypto-prefix and --crypto-threshold must be specified together');
  }
  return args;
}
export function parseLcov(text) {
  const records = [];
  let current = null;
  for (const line of text.split('\n')) {
    if (line.startsWith('SF:')) {
      current = { file: line.slice(3).trim(), linesFound: 0, linesHit: 0 };
    } else if (line.startsWith('DA:') && current) {
      const hits = Number(line.slice(3).split(',')[1]);
      current.linesFound += 1;
      if (hits > 0) current.linesHit += 1;
    } else if (line.startsWith('end_of_record') && current) {
      records.push(current);
      current = null;
    }
  }
  return records;
}
export function aggregate(records, filterFn) {
  let found = 0;
  let hit = 0;
  for (const r of records) {
    if (filterFn && !filterFn(r.file)) continue;
    found += r.linesFound;
    hit += r.linesHit;
  }
  return { found, hit, pct: found === 0 ? null : (hit / found) * 100 };
}
function main() {
  const args = parseArgs(process.argv.slice(2));
  const text = readFileSync(args.lcov, 'utf8');
  const cwd = process.cwd();
  const normalize = createSourcePathNormalizer(cwd);
  const all = parseLcov(text).map((r) => ({ ...r, file: normalize(r.file) }));
  const measured =
    args.includePrefix == null ? all : all.filter((r) => r.file.startsWith(args.includePrefix));
  if (args.includePrefix != null) {
    if (all.length > 0 && measured.length === 0) {
      console.error(
        `check-coverage: no SF: record in ${args.lcov} matches --include-prefix=${args.includePrefix}`,
      );
      process.exit(1);
    }
    console.log(
      `Restricted to --include-prefix=${args.includePrefix}: ${measured.length}/${all.length} records`,
    );
  }
  if (measured.length === 0) {
    console.error(`check-coverage: ${args.lcov} contains no SF: records (empty lcov)`);
    process.exit(1);
  }
  const unmeasured = args.sourceRoot == null ? [] : unmeasuredRecords(measured, args.sourceRoot);
  const records = [...measured, ...unmeasured];
  if (unmeasured.length > 0) {
    const lines = unmeasured.reduce((sum, r) => sum + r.linesFound, 0);
    console.log(
      `Unmeasured sources (not in lcov, counted as 0% under --source-root=${args.sourceRoot}): ${unmeasured.length} files, ${lines} lines`,
    );
    for (const r of unmeasured) console.log(`  ${r.file} (${r.linesFound} lines)`);
  }
  let failed = false;
  const overall = aggregate(records);
  if (overall.pct == null) {
    console.error(`FAIL: ${args.lcov} contains no measurable lines (overall linesFound is 0)`);
    failed = true;
  } else {
    console.log(
      `Overall line coverage: ${overall.hit}/${overall.found} (${overall.pct.toFixed(2)}%), threshold ${args.overall}%`,
    );
    if (overall.pct < args.overall) {
      console.error(
        `FAIL: overall coverage ${overall.pct.toFixed(2)}% is below threshold ${args.overall}%`,
      );
      failed = true;
    }
  }
  if (args.cryptoPrefix != null && args.cryptoThreshold != null) {
    const crypto = aggregate(records, (f) => f.startsWith(args.cryptoPrefix));
    if (crypto.pct == null) {
      console.error(`FAIL: no coverage records matched --crypto-prefix=${args.cryptoPrefix}`);
      failed = true;
    } else {
      console.log(
        `Crypto (${args.cryptoPrefix}) line coverage: ${crypto.hit}/${crypto.found} (${crypto.pct.toFixed(2)}%), threshold ${args.cryptoThreshold}%`,
      );
      if (crypto.pct < args.cryptoThreshold) {
        console.error(
          `FAIL: crypto coverage ${crypto.pct.toFixed(2)}% is below threshold ${args.cryptoThreshold}%`,
        );
        failed = true;
      }
    }
  }
  if (failed) process.exit(1);
}
if (isMainModule(import.meta.url)) {
  main();
}
