// test/interop/__tests__/generate-report.test.mjs
//
// test/interop/generate-report.mjs の集計ロジック・レポート生成ロジックの回帰テスト。
// 既知の入力マトリクスデータに対する集計結果・レポート構造を検証する
// （件数の取り違え、pass を fail と誤表示する等の不具合を生成前に検知するため）。
// Node 標準の test runner のみを使い、新規依存は追加しない。
// ランナー別のファイル名・生成元表示と、結果 JSON を残せなかった場合の合成は
// Linterly の 1 ディレクトリ 2000 行上限のため report/ 配下へ切り出してある。

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  buildReport,
  buildRows,
  countByStatus,
  escapeTableCell,
  reportDate,
} from '../generate-report.mjs';

const sampleResults = [
  { pair: 'interop:vericerts:didkit', status: 'pass' },
  { pair: 'interop:vericerts:sphereon', status: 'pass' },
  { pair: 'interop:vericerts:waltid', status: 'fail', reason: 'signature mismatch' },
  { pair: 'interop:sphereon:didkit', status: 'skipped', reason: 'not supported' },
];

describe('countByStatus', () => {
  it('regression: pass/fail/skipped を取り違えずに件数集計する', () => {
    assert.deepEqual(countByStatus(sampleResults), {
      passCount: 2,
      failCount: 1,
      skippedCount: 1,
      knownIncompatibleCount: 0,
    });
  });

  it('regression: 空配列では全ステータス0件', () => {
    assert.deepEqual(countByStatus([]), {
      passCount: 0,
      failCount: 0,
      skippedCount: 0,
      knownIncompatibleCount: 0,
    });
  });

  it('known-incompatible は fail にも skipped にも数えず、専用の件数にする', () => {
    assert.deepEqual(
      countByStatus([
        { pair: 'interop:a:b', status: 'known-incompatible', reason: 'x' },
        { pair: 'interop:c:d', status: 'fail', reason: 'y' },
      ]),
      { passCount: 0, failCount: 1, skippedCount: 0, knownIncompatibleCount: 1 },
    );
  });
});

describe('buildRows', () => {
  it('regression: fail を pass の絵文字で誤表示しない', () => {
    const rows = buildRows(sampleResults);
    const failRow = rows.split('\n').find((line) => line.includes('interop:vericerts:waltid'));
    assert.match(failRow, /❌ fail/);
    assert.doesNotMatch(failRow, /✅/);
  });

  it('regression: pass 行には✅を表示する', () => {
    const rows = buildRows(sampleResults);
    const passRow = rows.split('\n').find((line) => line.includes('interop:vericerts:didkit'));
    assert.match(passRow, /✅ pass/);
  });

  it('regression: 未知の status はそのまま表示する', () => {
    const rows = buildRows([{ pair: 'interop:a:b', status: 'timeout' }]);
    assert.match(rows, /\| `interop:a:b` \| timeout timeout \|/);
  });

  it('regression: reason 省略時は空欄で埋める', () => {
    const rows = buildRows([{ pair: 'interop:a:b', status: 'pass' }]);
    assert.match(rows, /\| `interop:a:b` \| ✅ pass \| {2}\|/);
  });
});

describe('buildRows: peer 由来 reason のエスケープ', () => {
  const hostile = 'HTTP 500: {"a":"x | y"}\nsecond line <script>alert(1)</script> & \\|';

  it('regression: |・改行・HTML を含む reason でも 1 行・4 パイプ区切り（3 列）のまま', () => {
    const rows = buildRows([{ pair: 'interop:a:b', status: 'fail', reason: hostile }]);
    assert.equal(rows.split('\n').length, 1);
    // エスケープされていない（直前が \ でない）パイプだけが列区切り: 先頭・2 つ・末尾の計 4 本。
    assert.equal(rows.match(/(?<!\\)\|/g).length, 4);
    assert.doesNotMatch(rows, /<script>/);
  });

  it('regression: バックスラッシュ直後の | もエスケープされた列区切りにならない', () => {
    assert.equal(escapeTableCell('a\\|b'), 'a\\\\\\|b');
  });
});

describe('buildReport', () => {
  const data = {
    generatedAt: '2026-09-24T12:00:00.000Z',
    results: sampleResults,
  };

  it('regression: 集計行に正しい件数を埋め込む', () => {
    const report = buildReport(data);
    assert.match(report, /集計: pass 2 \/ fail 1 \/ skipped 1/);
  });

  it('regression: タイトルに generatedAt の日付部分を使う', () => {
    const report = buildReport(data);
    assert.match(report, /^# 相互運用テスト結果マトリクス — 2026-09-24/);
  });

  it('regression: 各ペアの行がテーブルに含まれる', () => {
    const report = buildReport(data);
    for (const r of sampleResults) {
      assert.match(report, new RegExp(`\\| \`${r.pair}\` \\|`));
    }
  });

  it('regression: 結果が0件でもテーブルヘッダーは維持する', () => {
    const report = buildReport({ generatedAt: '2026-01-01T00:00:00.000Z', results: [] });
    assert.match(report, /集計: pass 0 \/ fail 0 \/ skipped 0/);
    assert.match(report, /\| ペア \| 結果 \| 理由 \|/);
  });
});

describe('reportDate', () => {
  it('regression: ISO8601文字列の先頭10文字を日付として返す', () => {
    assert.equal(reportDate('2026-09-24T12:00:00.000Z'), '2026-09-24');
  });
});
