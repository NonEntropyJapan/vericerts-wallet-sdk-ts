// test/interop/__tests__/report/fallback-pairs.test.mjs
//
// ドライバが結果 JSON を残せなかったときに fail を合成する経路の回帰テスト。
// SD-JWT ドライバの実行は `timeout` 付きで、ハングして SIGKILL されると `tee` が空ファイルを残す。
// 合成が無いとレポートも Issue も残らず（非ゲートの新版検知ジョブでは緑のまま、ゲート側では
// `JSON.parse` の throw で後続の起票ステップが丸ごとスキップされ）失敗が検知経路から落ちる。
//
// generate-report.test.mjs から切り出してある（Linterly の 1 ディレクトリ 2000 行上限のため）。
//
// 実行方法: リポジトリルートから
//   node --test test/interop/__tests__/report/fallback-pairs.test.mjs

import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { describe, it } from 'node:test';
import {
  buildNoResultsOutput,
  buildReport,
  countByStatus,
  loadResults,
  NO_RESULTS_REASON,
  parseFallbackPairs,
  reportDate,
} from '../../generate-report.mjs';

describe('buildNoResultsOutput（ドライバが結果 JSON を残せなかった場合の合成）', () => {
  // 新版候補の検知ジョブは全ステップが continue-on-error の非ゲートなので、ドライバが JSON を
  // 返せない（`:latest` が起動しない・pull できない）とレポートも Issue も残らずジョブが緑のまま
  // 終わる。「新版が起動すらしない」は新版破壊として最も起こりやすい形で、検知を落とすと
  // 起動失敗をレポートに残せない。
  const pairs = [
    'interop:waltid-issuer:vericerts:sd-jwt:next',
    'interop:vericerts:waltid-verifier:sd-jwt:next',
  ];

  it('渡したペアをすべて fail として合成する（skipped にはしない。起票対象は fail のみ）', () => {
    const output = buildNoResultsOutput(pairs);
    assert.deepEqual(
      output.results,
      pairs.map((pair) => ({ pair, status: 'fail', reason: NO_RESULTS_REASON })),
    );
  });

  it('合成結果の理由から「新版候補の起動に失敗した」と分かる', () => {
    const [result] = buildNoResultsOutput(pairs).results;
    assert.match(result.reason, /^driver-no-results: /);
    assert.match(result.reason, /イメージが起動しない/);
  });

  it('合成結果はそのままレポート・Issue 起票の入力形式になる', () => {
    const output = buildNoResultsOutput(pairs);
    assert.equal(reportDate(output.generatedAt).length, 10);
    assert.deepEqual(countByStatus(output.results), {
      passCount: 0,
      failCount: 2,
      skippedCount: 0,
      knownIncompatibleCount: 0,
    });
    const report = buildReport(output);
    assert.match(report, /集計: pass 0 \/ fail 2 \//);
    for (const pair of pairs) {
      assert.match(report, new RegExp(`\\| \`${pair}\` \\|`));
    }
  });
});

describe('loadResults / parseFallbackPairs（合成へ倒す条件と CLI 引数）', () => {
  const sampleResults = [
    { pair: 'interop:vericerts:didkit', status: 'pass' },
    { pair: 'interop:vericerts:waltid', status: 'fail', reason: 'signature mismatch' },
  ];

  const tempFile = (contents) => {
    const file = path.join(mkdtempSync(path.join(tmpdir(), 'interop-report-')), 'result.json');
    writeFileSync(file, contents);
    return file;
  };

  it('ファイルが無い / JSON が壊れている / results が空 のどれも undefined（合成へ倒す）', () => {
    assert.equal(loadResults(path.join(tmpdir(), 'interop-report-does-not-exist.json')), undefined);
    assert.equal(loadResults(tempFile('not json')), undefined);
    // `timeout` に殺されたドライバの `tee` が残す空ファイルもここで合成へ倒れる。
    assert.equal(loadResults(tempFile('')), undefined);
    assert.equal(loadResults(tempFile('{"generatedAt":"2026-11-09T18:00:00.000Z"}')), undefined);
    assert.equal(loadResults(tempFile('{"results":[]}')), undefined);
  });

  it('results が 1 件以上あればそのまま返す（合成しない）', () => {
    const data = { generatedAt: '2026-11-09T18:00:00.000Z', results: sampleResults };
    assert.deepEqual(loadResults(tempFile(JSON.stringify(data))), data);
  });

  it('--fallback-pairs はカンマ区切りで読み、指定が無ければ空（従来どおり読み込み失敗で落とす）', () => {
    assert.deepEqual(parseFallbackPairs(['/tmp/x.json', 'prefix']), []);
    assert.deepEqual(parseFallbackPairs(['/tmp/x.json', '--fallback-pairs=']), []);
    assert.deepEqual(
      parseFallbackPairs(['/tmp/x.json', 'prefix', '--fallback-pairs=interop:a:b,interop:c:d']),
      ['interop:a:b', 'interop:c:d'],
    );
  });
});
