const TEST_NAME = /(?:\.|_)(?:test|spec)\.[cm]?[jt]sx?$/;
export function checkTestResults(results, { expectedFiles, allowance = {}, label, prefix = '' }) {
  const problems = [];
  const { cases, files, declaredTests } = results;
  if (cases.length === 0)
    return [`${label}: 結果にテストが 1 件も無い (ランナーの失敗か出力の欠落)`];
  if (declaredTests !== null && declaredTests !== cases.length) {
    problems.push(
      `${label}: 宣言された件数 ${declaredTests} と数えた件数 ${cases.length} が違う (出力の欠落)`,
    );
  }
  const perFile = new Map();
  for (const testCase of cases) {
    const counts = perFile.get(testCase.file) ?? {
      passed: 0,
      failed: 0,
      skipped: 0,
      todo: 0,
      names: [],
    };
    counts[testCase.status] += 1;
    if (testCase.status !== 'passed') counts.names.push(`${testCase.status}: ${testCase.name}`);
    perFile.set(testCase.file, counts);
  }
  for (const [file, counts] of perFile) {
    const allowed = (allowance[`${prefix}${file}`] ?? []).reduce(
      (sum, entry) => sum + (entry.count ?? 1),
      0,
    );
    const skipped = counts.skipped + counts.todo;
    if (counts.failed > 0)
      problems.push(`${label}: ${file}: 失敗したテストが ${counts.failed} 件ある`);
    if (skipped > allowed) {
      problems.push(
        `${label}: ${file}: skip / todo されたテストが ${skipped} 件ある (許可 ${allowed} 件)。${counts.names.slice(0, 3).join(' / ')}`,
      );
    }
  }
  for (const [key, entries] of Object.entries(allowance)) {
    if (!key.startsWith(prefix)) continue;
    const counts = perFile.get(key.slice(prefix.length));
    const allowed = entries.reduce((sum, entry) => sum + (entry.count ?? 1), 0);
    const skipped = counts === undefined ? 0 : counts.skipped + counts.todo;
    if (skipped < allowed) {
      problems.push(
        `${label}: ${key}: 許可 ${allowed} 件が実体 ${skipped} 件より多い。RESULT_ALLOWANCE から外す`,
      );
    }
  }
  for (const file of expectedFiles) {
    const counts = perFile.get(file);
    if (counts === undefined) {
      problems.push(
        `${label}: ${file}: テストファイルなのに結果に 1 件も無い (ランナーが拾っていない / 本体が 1 回も走らない / it.each の表が空)`,
      );
    }
  }
  for (const file of files) {
    if (!perFile.has(file) && TEST_NAME.test(file) && !expectedFiles.includes(file)) {
      problems.push(`${label}: ${file}: 1 件も実行されていない`);
    }
  }
  return problems;
}
export function expectedTestFiles(files, directory, excludedDirectories = []) {
  const prefix = directory === '' ? '' : `${directory}/`;
  return files
    .filter((file) => file.startsWith(prefix) && TEST_NAME.test(file))
    .map((file) => file.slice(prefix.length))
    .filter((file) => !excludedDirectories.some((dir) => file.startsWith(`${dir}/`)))
    .sort();
}
