import { readFileSync } from 'node:fs';
import path from 'node:path';
import { listRepoFiles } from '../repo-files.mjs';
import { executableLinesOf } from './executable-lines.mjs';
export const TEST_OR_GENERATED = [
  /(^|\/)__tests__\//,
  /(^|\/)__mocks__\//,
  /\.(?:test|spec)\.[cm]?[jt]sx?$/,
  /\.d\.ts$/,
  /\.fixtures?\.[cm]?[jt]sx?$/,
  /(^|\/)test-setup\.[cm]?[jt]s$/,
];
const SOURCE_RE = /\.(?:[cm]?[jt]s|[jt]sx)$/;
export const UNMEASURED_EXCLUSIONS = [];
export function listTrackedFiles(cwd) {
  return listRepoFiles(cwd, true);
}
export function listTrackedSources(sourceRoot, cwd) {
  const prefix = `${sourceRoot.replace(/\/$/, '')}/`;
  return listTrackedFiles(cwd)
    .filter((file) => file.startsWith(prefix) && SOURCE_RE.test(file))
    .filter((file) => !TEST_OR_GENERATED.some((re) => re.test(file)));
}
export function unmeasuredRecords(records, sourceRoot, options = {}) {
  const cwd = options.cwd ?? process.cwd();
  const exclusions = options.exclusions ?? UNMEASURED_EXCLUSIONS;
  const sources = (options.list ?? listTrackedSources)(sourceRoot, cwd);
  if (sources.length === 0) {
    throw new Error(
      `--source-root=${sourceRoot}: git 管理下のソースが 1 件も無い（パスの誤りは空振りになる）`,
    );
  }
  const measured = new Set(records.map((record) => record.file));
  const read = options.read ?? ((file) => readFileSync(path.join(cwd, file), 'utf8'));
  const found = [];
  for (const file of sources) {
    if (measured.has(file) || exclusions.some(({ pattern }) => pattern.test(file))) continue;
    const linesFound = executableLinesOf(file, read(file));
    if (linesFound > 0) found.push({ file, linesFound, linesHit: 0, unmeasured: true });
  }
  return found;
}
