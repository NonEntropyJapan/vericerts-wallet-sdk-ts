// test/interop/__tests__/report/report-naming.test.mjs
//
// generate-report.mjs の「どのランナーの結果か」をレポートに残す部分の回帰テスト。
// Nightly が VC 発行・検証 / DID 解決 / walt.id SD-JWT の複数ランナーを同じ日に回すようになり、
// 出力ファイル名と本文の生成元表示がランナーごとに分かれないと結果が黙って混ざる。
//
// generate-report.test.mjs から切り出してある（Linterly の 1 ディレクトリ 2000 行上限のため）。
//
// 実行方法: リポジトリルートから
//   node --test test/interop/__tests__/report/report-naming.test.mjs

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { buildReport, reportFileName } from '../../generate-report.mjs';

describe('reportFileName', () => {
  it('prefix 省略時は従来どおり matrix-<date>.md を返す', () => {
    assert.equal(reportFileName('2026-11-09T18:00:00.000Z'), 'matrix-2026-11-09.md');
  });

  it('prefix を変えるとランナーごとに別ファイルへ書き分けられる', () => {
    // 同じ日に 2 つのランナーの結果を同じ名前へ書くと、後から走った方が前の結果を黙って
    // 上書きする。prefix が実際にファイル名を分けることを固定する。
    const generatedAt = '2026-11-09T18:00:00.000Z';
    assert.equal(reportFileName(generatedAt, 'did-resolution'), 'did-resolution-2026-11-09.md');
    assert.notEqual(reportFileName(generatedAt, 'did-resolution'), reportFileName(generatedAt));
  });
});

describe('buildReport の生成元表示', () => {
  it('generator が無い結果では従来の run-peer-matrix.mjs を表示する', () => {
    const report = buildReport({ generatedAt: '2026-11-09T18:00:00.000Z', results: [] });
    assert.match(report, /生成: `test\/interop\/run-peer-matrix\.mjs`/);
  });

  it('generator を持つ結果ではそのランナー名を表示する', () => {
    const report = buildReport({
      generatedAt: '2026-11-09T18:00:00.000Z',
      generator: 'test/interop/run-did-resolution-matrix.mjs',
      results: [],
    });
    assert.match(report, /生成: `test\/interop\/run-did-resolution-matrix\.mjs`/);
  });
});
