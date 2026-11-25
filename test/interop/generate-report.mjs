#!/usr/bin/env node
// test/interop/generate-report.mjs
//
// `run-peer-matrix.mjs` の JSON 出力から `test/interop/reports/matrix-<date>.md` を生成する。
//
// 使い方: node test/interop/run-peer-matrix.mjs > /tmp/matrix.json
//         node test/interop/generate-report.mjs /tmp/matrix.json [report-name-prefix]
//                                                [--fallback-pairs=<pair>[,<pair>…]]

import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { isMainModule } from '../../scripts/lib/is-main-module.mjs';

export const STATUS_EMOJI = { pass: '✅', fail: '❌', skipped: '⚠️', 'known-incompatible': '🟡' };

/** `generatedAt`（ISO8601）からレポートの日付部分（先頭10文字）を取り出す。 */
export function reportDate(generatedAt) {
  return generatedAt.slice(0, 10);
}

/** 結果 JSON に `generator` が無い場合のレポート生成元（従来からの唯一のランナー）。 */
const DEFAULT_GENERATOR = 'test/interop/run-peer-matrix.mjs';

/**
 * レポートのファイル名（`<prefix>-<date>.md`）。
 *
 * ランナーが複数になった（VC 発行・検証マトリクスと DID 解決マトリクス）ため、
 * prefix で書き分ける。既定は従来どおり `matrix-<date>.md` で、同じ日に 2 つのランナーの結果を
 * 同じ名前へ書いて**後から走った方が前の結果を黙って上書きする**のを防ぐ。
 */
export function reportFileName(generatedAt, prefix = 'matrix') {
  return `${prefix}-${reportDate(generatedAt)}.md`;
}

/**
 * peer の応答本文・stderr 由来の `reason` を Markdown テーブルの 1 セルへ安全に埋め込む。
 * 改行は空白へ畳み（行が途中で切れて表が崩れるのを防ぐ）、`\` と `|` はエスケープして列分割を防ぎ、
 * `<` `>` `&` は HTML として解釈されないよう実体参照にする。
 */
export function escapeTableCell(text) {
  return String(text)
    .replace(/\r\n|[\r\n\u2028\u2029]/g, ' ')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/\\/g, '\\\\')
    .replace(/\|/g, '\\|');
}

/** ペアごとの結果を Markdown テーブル行に組み立てる。 */
export function buildRows(results) {
  return results
    .map(
      (r) =>
        `| \`${r.pair}\` | ${STATUS_EMOJI[r.status] ?? r.status} ${r.status} | ${escapeTableCell(r.reason ?? '')} |`,
    )
    .join('\n');
}

/** pass/fail/skipped/known-incompatible の件数を集計する。 */
export function countByStatus(results) {
  return {
    passCount: results.filter((r) => r.status === 'pass').length,
    failCount: results.filter((r) => r.status === 'fail').length,
    skippedCount: results.filter((r) => r.status === 'skipped').length,
    knownIncompatibleCount: results.filter((r) => r.status === 'known-incompatible').length,
  };
}

/** `run-peer-matrix.mjs` の JSON 出力からレポート本文（Markdown）を組み立てる。 */
export function buildReport(data) {
  const date = reportDate(data.generatedAt);
  const rows = buildRows(data.results);
  const { passCount, failCount, skippedCount, knownIncompatibleCount } = countByStatus(
    data.results,
  );

  return `# 相互運用テスト結果マトリクス — ${date}

契約: [Interop README](../README.md) / [matrix.json](../contracts/matrix.json)。
生成: \`${data.generator ?? DEFAULT_GENERATOR}\`（${data.generatedAt}）。

集計: pass ${passCount} / fail ${failCount} / skipped ${skippedCount} / known-incompatible ${knownIncompatibleCount}

| ペア | 結果 | 理由 |
| --- | --- | --- |
${rows}
`;
}

/** 「ドライバが結果を残せなかった」ことを表す合成結果の理由（Issue 自動起票の本文にも載る）。 */
export const NO_RESULTS_REASON =
  'driver-no-results: ドライバが結果 JSON を残さなかった（イメージが起動しない・pull できない等）。実行ログで起動の失敗を確認する';

/**
 * 結果 JSON をドライバが残せなかった場合に合成するペア結果。
 *
 * 新版候補（mutable tag）の検知ジョブは全ステップが `continue-on-error` の非ゲートなので、
 * ドライバが JSON を返せないと（`:latest` が起動しない・pull できない等。**新版破壊として最も
 * 起こりやすい形**）レポートも Issue も残らずジョブが緑のまま終わる。それでは
 * 新版候補の起動失敗を結果として残せない。
 * 非ゲートのまま、検知だけは残すためにペアの `fail` を合成する。
 */
export function buildNoResultsOutput(pairs) {
  return {
    generatedAt: new Date().toISOString(),
    generator: 'test/interop/generate-report.mjs（ドライバの結果が無いため合成）',
    results: pairs.map((pair) => ({ pair, status: 'fail', reason: NO_RESULTS_REASON })),
  };
}

/**
 * 読めて `results` が 1 件以上ある結果 JSON だけを返す（それ以外は undefined）。
 * 「ファイルが無い」「JSON として壊れている」「`results` が空」はどれも**ドライバが結果を
 * 残せなかった**ことを意味するので、合成へ倒す判定として同じに扱う。
 */
export function loadResults(inputPath) {
  try {
    const data = JSON.parse(readFileSync(inputPath, 'utf8'));
    return Array.isArray(data?.results) && data.results.length > 0 ? data : undefined;
  } catch {
    return undefined;
  }
}

const FALLBACK_PAIRS_FLAG = '--fallback-pairs=';

/** `--fallback-pairs=<pair>[,<pair>…]` のペア名（指定が無ければ空配列 = 合成しない）。 */
export function parseFallbackPairs(args) {
  const flag = args.find((arg) => arg.startsWith(FALLBACK_PAIRS_FLAG));
  return (flag?.slice(FALLBACK_PAIRS_FLAG.length) ?? '').split(',').filter((pair) => pair !== '');
}

function main() {
  const args = process.argv.slice(2);
  // 第 2 引数はレポートのファイル名 prefix（省略時は従来の `matrix`）。
  const [inputPath, prefix] = args.filter((arg) => !arg.startsWith('--'));
  if (!inputPath) {
    console.error(
      'usage: node generate-report.mjs <matrix-result.json> [report-name-prefix] [--fallback-pairs=<pair>[,<pair>…]]',
    );
    process.exitCode = 1;
    process.exit();
  }
  const fallbackPairs = parseFallbackPairs(args);

  let data = loadResults(inputPath);
  if (data === undefined) {
    if (fallbackPairs.length === 0) {
      // `--fallback-pairs` を渡していないゲート対象の呼び出しは従来どおり読み込み失敗で落とす
      // （結果 JSON が無いこと自体をジョブの失敗として扱う）。
      data = JSON.parse(readFileSync(inputPath, 'utf8'));
    } else {
      // 後続の処理が同じ結果を読めるよう、入力 JSON へ書き戻す。
      data = buildNoResultsOutput(fallbackPairs);
      writeFileSync(inputPath, `${JSON.stringify(data, null, 2)}\n`);
    }
  }
  const report = buildReport(data);

  const sdkRoot = new URL('../../', import.meta.url);
  const outDir = fileURLToPath(new URL('./reports/', import.meta.url));
  mkdirSync(outDir, { recursive: true });
  const outPath = path.join(outDir, reportFileName(data.generatedAt, prefix));
  writeFileSync(outPath, report);
  console.log(`wrote ${path.relative(fileURLToPath(sdkRoot), outPath)}`);
}

// CLI から直接実行された場合だけ走らせる（`node --test` からの import では走らせない）。
if (isMainModule(import.meta.url)) {
  main();
}
