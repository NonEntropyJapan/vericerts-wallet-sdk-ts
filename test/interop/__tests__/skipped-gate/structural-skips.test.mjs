// test/interop/__tests__/skipped-gate/structural-skips.test.mjs
//
// ゲート用の厳格モード（`--fail-on-skipped`）の判定と、`pairs.json` の
// `didResolution.structuralSkips` 許可リストの回帰テスト。
//
// Release Gate は「実行されるはずなのに実行されなかった」ペアでリリースを止める。ここで固定するのは
// 「許可リストが成功に見せかけるためのペア除外になっていない」こと — 登録したペアが skipped 以外に
// なったり結果から消えたりしたら違反になり、登録外の skipped は 1 件でも違反になる。
//
// 許可リストを持つのは DID 解決マトリクスだけである。VC マトリクスの native 発行 × uniform 検証
// 4 ペアは、決め打ちの `skipped` をやめて実際に試行し `knownIncompatible`で扱うことにした
// ため、許可リストを持たない。
//
// 実行方法: node --test test/interop/__tests__/skipped-gate/structural-skips.test.mjs

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { checkStructuralSkips, evaluateMatrix } from '../../lib/skipped-gate.mjs';

const PAIRS = JSON.parse(readFileSync(new URL('../../pairs.json', import.meta.url), 'utf8'));

const ENTRIES = [
  { pair: 'interop:a:b', reasonIncludes: 'format-incompatible', note: '設計上の形式差' },
];
const skipped = (pair, reason) => ({ pair, status: 'skipped', reason });

test('許可リストのペアが登録どおりの理由で skipped なら違反にしない', () => {
  const results = [skipped('interop:a:b', 'format-incompatible: LD-Proof と JWT-VC の形式差')];
  assert.deepEqual(checkStructuralSkips(results, ENTRIES), []);
});

test('許可リスト外の skipped は 1 件でも違反になる', () => {
  const results = [
    skipped('interop:a:b', 'format-incompatible: LD-Proof と JWT-VC の形式差'),
    skipped('interop:ebsi:prerequisite', 'prerequisite-missing: 環境変数が未設定'),
  ];
  const violations = checkStructuralSkips(results, ENTRIES);
  assert.equal(violations.length, 1);
  assert.match(violations[0], /interop:ebsi:prerequisite/);
  assert.match(violations[0], /prerequisite-missing/);
});

test('許可リストのペアが pass / fail に変わったら違反になる（想定外の変化）', () => {
  for (const status of ['pass', 'fail', 'known-incompatible']) {
    const violations = checkStructuralSkips([{ pair: 'interop:a:b', status }], ENTRIES);
    assert.equal(violations.length, 1, status);
    assert.match(violations[0], new RegExp(`${status} になった`));
  }
});

test('許可リストのペアが結果から消えたら違反になる（ペアの暗黙の除外を検知）', () => {
  const violations = checkStructuralSkips([{ pair: 'interop:x:y', status: 'pass' }], ENTRIES);
  assert.deepEqual(violations, ['interop:a:b: 構造的な skipped として登録されたペアが結果に無い']);
});

test('許可リストのペアが登録外の理由で skipped なら違反になる', () => {
  const results = [skipped('interop:a:b', 'prerequisite-missing: 環境変数が未設定')];
  const violations = checkStructuralSkips(results, ENTRIES);
  assert.equal(violations.length, 1);
  assert.match(violations[0], /登録と違う理由/);
});

test('登録の形式が不正・二重登録なら例外にする（黙って無視しない）', () => {
  assert.throws(() => checkStructuralSkips([], [{ pair: 'interop:a:b', reasonIncludes: '' }]));
  assert.throws(() => checkStructuralSkips([], [ENTRIES[0], ENTRIES[0]]), /二重に登録/);
});

test('通常モードは skipped / known-incompatible で終了コード 0、fail だけが 1', () => {
  const results = [
    skipped('interop:ebsi:prerequisite', 'prerequisite-missing'),
    { pair: 'interop:c:d', status: 'known-incompatible', reason: '登録済みの形式不一致' },
  ];
  assert.deepEqual(evaluateMatrix(results), { violations: [], exitCode: 0 });
  assert.equal(evaluateMatrix([...results, { pair: 'interop:e:f', status: 'fail' }]).exitCode, 1);
});

test('厳格モードは許可リスト外の skipped で終了コードを 1 にする', () => {
  const results = [skipped('interop:ebsi:prerequisite', 'prerequisite-missing: 未設定')];
  const strict = evaluateMatrix(results, { strict: true, structuralSkips: ENTRIES });
  assert.equal(strict.exitCode, 1);
  assert.equal(strict.violations.length, 2); // 登録外の skipped + 登録ペアが結果に無い
});

test('厳格モードでも known-incompatible は終了コード 0 のまま', () => {
  const results = [
    { pair: 'interop:c:d', status: 'known-incompatible', reason: '登録済みの形式不一致' },
  ];
  assert.deepEqual(evaluateMatrix(results, { strict: true, structuralSkips: [] }), {
    violations: [],
    exitCode: 0,
  });
});

test('VC マトリクスは構造的な skipped の許可リストを持たない（4 ペアは試行して knownIncompatible で扱う）', () => {
  assert.equal(
    PAIRS.structuralSkips,
    undefined,
    'pairs.json に VC マトリクスの許可リストが残っている',
  );
  // 4 ペアは `knownIncompatible` 側に Issue 番号付きで登録されている（詳細は
  // run-peer-matrix.native-format.test.mjs が固定する）。
  const registered = new Set(PAIRS.knownIncompatible.map((entry) => entry.pair));
  for (const native of PAIRS.nativePeers) {
    for (const uniform of PAIRS.uniformPeers) {
      assert.ok(
        registered.has(`interop:${native.name}:${uniform.name}`),
        `interop:${native.name}:${uniform.name} が knownIncompatible に無い`,
      );
    }
  }
});

test('pairs.json の didResolution.structuralSkips は 13 件ちょうどで、全ペアが matrix の実在ペア', () => {
  const matrixPairs = Object.entries(PAIRS.didResolution.matrix).flatMap(([method, peerNames]) =>
    peerNames.map((peerName) => `interop:did-resolve:${method}:${peerName}`),
  );
  const registered = PAIRS.didResolution.structuralSkips.map((entry) => entry.pair);
  // 黙った増減をここで落とす（構造的な skip の許可リストはこの 13 件だけ）。
  assert.equal(registered.length, 13);
  assert.equal(new Set(registered).size, registered.length, '同じペアが二重に登録されている');
  for (const pair of registered) {
    assert.ok(matrixPairs.includes(pair), `${pair} は didResolution.matrix から導かれないペア名`);
  }
  for (const entry of PAIRS.didResolution.structuralSkips) {
    assert.ok(
      ['resolver-unavailable', 'fixture-missing'].includes(entry.reasonIncludes),
      `${entry.pair}: 構造的な skip 以外の理由が登録されている（${entry.reasonIncludes}）`,
    );
  }
});

test('VC マトリクスの EBSI 前提確認ペアは許可リストに入れない（変数未登録ならゲートで失敗させる）', () => {
  const pairs = PAIRS.didResolution.structuralSkips.map((entry) => entry.pair);
  assert.ok(
    !pairs.includes('interop:ebsi:prerequisite'),
    'interop:ebsi:prerequisite が許可リストに入っている',
  );
});

test('DID 解決の EBSI 2 ペアは fixture-missing で登録する（変数未設定なら理由違いで違反になる）', () => {
  // `resolvePair` は `requiresEnv` を fixture より先に見るため、`EBSI_SANDBOX_BASE_URL` が未設定の
  // あいだはこの 2 ペアが `prerequisite-missing` になり、登録と違う理由としてゲート違反になる
  // （運用前提の未充足を検知し続ける）。変数の登録後だけ `fixture-missing` になり許容される。
  for (const pair of ['interop:did-resolve:web:ebsi', 'interop:did-resolve:ebsi:ebsi']) {
    const entry = PAIRS.didResolution.structuralSkips.find((e) => e.pair === pair);
    assert.ok(entry, `${pair} が許可リストに無い`);
    assert.equal(entry.reasonIncludes, 'fixture-missing');
  }
});
