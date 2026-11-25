// test/interop/lib/skipped-gate.mjs
//
// ゲート用の厳格モード（ランナーの `--fail-on-skipped`）と Job Summary の出力。
//
// Release Gate では「実行されるはずなのに実行されなかった」ペアでリリースを止める。`skipped` は
// Nightly では終了コードに影響しないが、ゲートでは失敗にする（EBSI の `prerequisite-missing` を
// 含む。運用側が `EBSI_SANDBOX_BASE_URL` を用意するまでゲートは通らない）。
//
// 「理由一致」の判定は、この運用前提の未充足をそのまま検知する仕組みにもなっている。DID 解決の
// EBSI 2 ペア（`interop:did-resolve:web:ebsi` / `interop:did-resolve:ebsi:ebsi`）は許可リストに
// `fixture-missing`（fixture 未整備。did:web の文書ホストと did:ebsi のテスト DID が未確定で、
// 環境変数では解消しない）で登録してあるが、
// `EBSI_SANDBOX_BASE_URL` が未設定のあいだは `prerequisite-missing` が先に当たるため、登録と違う
// 理由としてゲートが落ちる。変数の登録後だけ登録どおりの理由になり、ゲートが通りうる。
//
// ただし設計上つねに `skipped` になるペア（解決経路を公開していないピア、fixture 未整備のメソッド）
// まで失敗にすると、DID 解決マトリクスのゲートが永久に通らない。そこで `pairs.json` の
// `didResolution.structuralSkips` に**ペア名と理由を明示した許可リスト**（13 件）を持ち、
// `knownIncompatible` と同じ「理由一致・想定外の変化の検知」で扱う:
//
//   - 許可リストのペアが登録どおりの理由で skipped → 許容（違反にしない）
//   - 許可リストのペアが pass / fail / known-incompatible になった → 違反（非互換の状況が変わった）
//   - 許可リストのペアが結果に無い → 違反（マトリクスから黙って落ちた）
//   - 許可リストのペアが登録外の理由で skipped → 違反（別の理由で止まっている）
//   - 許可リスト外のペアが skipped → 違反（前提未充足・退行）
//
// 成功に見せかけるためのペア除外ではない: 件数と理由が設定に固定され、増減がレビューで見える。
//
// VC マトリクス（`run-peer-matrix.mjs`）は許可リストを渡さない（`structuralSkips` は空）。native ピアの
// LD-Proof × uniform ピアの JWT-VC 検証という構造的な非互換は、決め打ちの `skipped` をやめて実際に
// 試行し、`pairs.json` の `knownIncompatible` で扱うことにしたため。
// この関数自体は両ランナーで共用する（DID 解決側だけが許可リストを渡す）。

import { appendFileSync } from 'node:fs';
import { escapeTableCell } from '../generate-report.mjs';

/** 集計に出す結果の status（`generate-report.mjs` と同じ並び）。 */
const STATUSES = ['pass', 'fail', 'skipped', 'known-incompatible'];

/**
 * 登録 1 件の形式を確かめる。不正な登録を黙って無視すると、typo の 1 件が「どのペアにも
 * 一致しない」まま構造的な skip をゲート違反に戻してしまう（`known-incompatible.mjs` と同じ方針）。
 */
function assertEntry(entry) {
  for (const field of ['pair', 'reasonIncludes', 'note']) {
    if (typeof entry?.[field] !== 'string' || entry[field] === '') {
      throw new Error(
        `structuralSkips: ${field} は空でない文字列が必要 (${JSON.stringify(entry)})`,
      );
    }
  }
}

/**
 * 厳格モードの違反を列挙する。
 *
 * @param {Array<{pair: string, status: string, reason?: string}>} results マトリクスの結果。
 * @param {Array<{pair: string, reasonIncludes: string, note: string}>} entries `structuralSkips`。
 * @returns {string[]} 違反（空 = 合格）。
 * @throws 登録の形式が不正、または同じペアが二重に登録されている場合。
 */
export function checkStructuralSkips(results, entries = []) {
  const byPair = new Map();
  for (const entry of entries) {
    assertEntry(entry);
    if (byPair.has(entry.pair)) {
      throw new Error(`structuralSkips: ${entry.pair} が二重に登録されている`);
    }
    byPair.set(entry.pair, entry);
  }

  const violations = [];
  const seen = new Set();
  for (const result of results) {
    const entry = byPair.get(result.pair);
    if (entry === undefined) {
      if (result.status === 'skipped') {
        violations.push(
          `${result.pair}: 実行されるはずのペアが skipped になった（${result.reason ?? '理由なし'}）`,
        );
      }
      continue;
    }
    seen.add(result.pair);
    if (result.status !== 'skipped') {
      violations.push(
        `${result.pair}: 構造的な skipped として登録されたペアが ${result.status} になった（${entry.note}）。pairs.json の structuralSkips を見直す`,
      );
      continue;
    }
    if (!String(result.reason ?? '').includes(entry.reasonIncludes)) {
      violations.push(
        `${result.pair}: 登録と違う理由で skipped になった（期待: ${entry.reasonIncludes} / 実際: ${result.reason ?? '理由なし'}）`,
      );
    }
  }
  for (const pair of byPair.keys()) {
    if (!seen.has(pair)) {
      violations.push(`${pair}: 構造的な skipped として登録されたペアが結果に無い`);
    }
  }
  return violations;
}

/**
 * ランナーの終了コードを決める。
 *
 * 通常モード（Nightly の呼び出し）は従来どおり `fail` が 1 件でもあるときだけ 1 で、`skipped` /
 * `known-incompatible` は 0 のまま。厳格モード（ゲート）はこれに `structuralSkips` の違反を足す。
 */
export function evaluateMatrix(results, { strict = false, structuralSkips = [] } = {}) {
  const violations = strict ? checkStructuralSkips(results, structuralSkips) : [];
  const failed = results.some((result) => result.status === 'fail');
  return { violations, exitCode: failed || violations.length > 0 ? 1 : 0 };
}

/**
 * Job Summary 用の Markdown。件数の内訳と、pass 以外のペアの名前・理由を出す
 * （`$GITHUB_STEP_SUMMARY` は artifact を開かずに失敗理由を見るための画面）。
 */
export function formatStatusSummary(title, results) {
  const counts = STATUSES.map(
    (status) => `${status} ${results.filter((r) => r.status === status).length}`,
  ).join(' / ');
  const noteworthy = results.filter((result) => result.status !== 'pass');
  const table =
    noteworthy.length === 0
      ? ['pass 以外のペアは無い。']
      : [
          '| ペア | 状態 | 理由 |',
          '| --- | --- | --- |',
          ...noteworthy.map(
            (r) => `| \`${r.pair}\` | ${r.status} | ${escapeTableCell(r.reason ?? '')} |`,
          ),
        ];
  return [
    '',
    `### ${title}`,
    '',
    `ペア数 ${results.length} 件中: ${counts}`,
    '',
    ...table,
    '',
  ].join('\n');
}

/**
 * `$GITHUB_STEP_SUMMARY` が設定されていれば Markdown を追記する（CI 以外では何もしない）。
 * 結果 JSON は stdout の契約なので、サマリは必ず別の出力先へ書く。
 */
export function appendJobSummary(markdown, env = process.env, appendImpl = appendFileSync) {
  const file = env.GITHUB_STEP_SUMMARY;
  if (typeof file !== 'string' || file === '') return false;
  appendImpl(file, markdown);
  return true;
}
