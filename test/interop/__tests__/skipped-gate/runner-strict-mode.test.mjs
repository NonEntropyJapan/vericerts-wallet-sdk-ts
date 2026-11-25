// test/interop/__tests__/skipped-gate/runner-strict-mode.test.mjs
//
// 両ランナーの CLI 本体（`main`）が `--fail-on-skipped` を実設定に繋いでいることと、Job Summary の
// 内容を固定する。VC マトリクスは許可リストを持たず（`skipped` は 1 件でも失敗）、
// DID 解決マトリクスだけが `pairs.json` の `didResolution.structuralSkips` を読む。
//
// Nightly は引数なしで呼ぶので終了コードの判定は従来どおり `fail` のみ。ゲート
// でだけ `--fail-on-skipped` を付けて `skipped` を失敗にする。
//
// 実行方法: node --test test/interop/__tests__/skipped-gate/runner-strict-mode.test.mjs

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { appendJobSummary, formatStatusSummary } from '../../lib/skipped-gate.mjs';
import { main as didResolutionMain } from '../../run-did-resolution-matrix.mjs';
import { main as peerMatrixMain } from '../../run-peer-matrix.mjs';
import { composePortStub, recordingFetch } from '../did-resolution/fixtures.mjs';

const PAIRS = JSON.parse(readFileSync(new URL('../../pairs.json', import.meta.url), 'utf8'));

const STRICT_ARGV = ['node', 'runner.mjs', '--fail-on-skipped'];
const PLAIN_ARGV = ['node', 'runner.mjs'];

/** 実設定の native 発行 × uniform 検証 4 ペア（試行した結果が `known-incompatible` に畳まれた形）。 */
const NATIVE_UNIFORM_PAIRS = PAIRS.nativePeers.flatMap((native) =>
  PAIRS.uniformPeers.map((uniform) => `interop:${native.name}:${uniform.name}`),
);
const nativeUniformResults = () =>
  NATIVE_UNIFORM_PAIRS.map((pair) => ({
    pair,
    status: 'known-incompatible',
    reason: `[${pair}] アダプタの入口検査が拒否する — jwt is required (string)`,
  }));

/** `main` を結果固定で 1 回実行し、終了コードと `::error::` 出力を返す。 */
async function runMain(main, { argv, results }) {
  const errors = [];
  const exitCode = await main({
    argv,
    runImpl: async () => ({ generatedAt: '2026-11-09T00:00:00.000Z', results }),
    env: {},
    log: () => {},
    error: (line) => errors.push(line),
  });
  return { exitCode, errors };
}

test('厳格モードでも native × uniform の 4 ペアが known-incompatible なら終了コード 0', async () => {
  const results = [
    ...nativeUniformResults(),
    { pair: 'interop:vericerts:vericerts', status: 'pass' },
  ];
  const { exitCode, errors } = await runMain(peerMatrixMain, { argv: STRICT_ARGV, results });
  assert.equal(exitCode, 0);
  assert.deepEqual(errors, []);
});

test('厳格モードで 4 ペアのうち 1 つが fail なら終了コードは非 0（unexpected-pass / 別原因）', async () => {
  for (const reason of ['unexpected-pass: 非互換が解消した可能性', 'issue failed: key not found']) {
    const [first, ...rest] = nativeUniformResults();
    const results = [{ pair: first.pair, status: 'fail', reason }, ...rest];
    const { exitCode } = await runMain(peerMatrixMain, { argv: STRICT_ARGV, results });
    assert.equal(exitCode, 1, reason);
  }
});

test('厳格モードは 4 ペアが skipped に戻ったら失敗にする（許可リストを持たない）', async () => {
  const [first, ...rest] = nativeUniformResults();
  const results = [
    {
      pair: first.pair,
      status: 'skipped',
      reason: 'format-incompatible: 決め打ちの skipped へ退行',
    },
    ...rest,
  ];
  const { exitCode, errors } = await runMain(peerMatrixMain, { argv: STRICT_ARGV, results });
  assert.equal(exitCode, 1);
  assert.equal(errors.length, 1);
  assert.match(errors[0], new RegExp(`^::error::${first.pair}: `));
});

test('厳格モードは EBSI の prerequisite-missing を失敗にする', async () => {
  const results = [
    ...nativeUniformResults(),
    {
      pair: 'interop:ebsi:prerequisite',
      status: 'skipped',
      reason: 'prerequisite-missing: 環境変数 EBSI_SANDBOX_BASE_URL が未設定',
    },
  ];
  const { exitCode, errors } = await runMain(peerMatrixMain, { argv: STRICT_ARGV, results });
  assert.equal(exitCode, 1);
  assert.equal(errors.length, 1);
  assert.match(errors[0], /^::error::interop:ebsi:prerequisite: /);
});

test('--fail-on-skipped が無ければ EBSI の prerequisite-missing でも終了コード 0（Nightly の呼び出し）', async () => {
  const results = [
    ...nativeUniformResults(),
    { pair: 'interop:ebsi:prerequisite', status: 'skipped', reason: 'prerequisite-missing' },
  ];
  const { exitCode, errors } = await runMain(peerMatrixMain, { argv: PLAIN_ARGV, results });
  assert.equal(exitCode, 0);
  assert.deepEqual(errors, []);
});

test('厳格モードは walt.id の想定外の skip も失敗にする（許可リストに無い）', async () => {
  const results = [
    ...nativeUniformResults(),
    { pair: 'interop:waltid-issuer:vericerts', status: 'skipped', reason: '公開ホスト検査で skip' },
  ];
  const { exitCode, errors } = await runMain(peerMatrixMain, { argv: STRICT_ARGV, results });
  assert.equal(exitCode, 1);
  assert.match(errors[0], /interop:waltid-issuer:vericerts/);
});

test('厳格モードでも fail が無ければ known-incompatible は終了コードを変えない', async () => {
  const results = [
    ...nativeUniformResults(),
    {
      pair: 'interop:vericerts:veramo',
      status: 'known-incompatible',
      reason: '[interop:vericerts:veramo] 既知',
    },
  ];
  const { exitCode } = await runMain(peerMatrixMain, { argv: STRICT_ARGV, results });
  assert.equal(exitCode, 0);
});

/**
 * DID 解決マトリクスを実設定（`pairs.json`）で 1 回実行し、終了コードと違反ペア名を返す。
 * 外部 I/O はすべてスタブ（`recordingFetch` / `composePortStub`）で、`env` だけを差し替えて
 * 「運用前提（`EBSI_SANDBOX_BASE_URL`）が未充足のとき / 充足したとき」の両方を駆動する。
 */
async function runDidResolutionMain(argv, env) {
  const errors = [];
  const exitCode = await didResolutionMain({
    argv,
    runImpl: () =>
      import('../../run-did-resolution-matrix.mjs').then((m) =>
        m.run({ fetchImpl: recordingFetch(), spawnImpl: composePortStub(), env }),
      ),
    env: {},
    log: () => {},
    error: (line) => errors.push(line),
  });
  const violatedPairs = errors
    .map((line) => line.replace('::error::', '').split(':').slice(0, 4).join(':'))
    .sort();
  return { exitCode, errors, violatedPairs };
}

test('DID 解決マトリクスは EBSI_SANDBOX_BASE_URL が未設定なら EBSI の 2 ペアを理由違いで違反にする', async () => {
  const { exitCode, errors, violatedPairs } = await runDidResolutionMain(STRICT_ARGV, {});
  assert.equal(exitCode, 1);
  assert.deepEqual(violatedPairs, [
    'interop:did-resolve:ebsi:ebsi',
    'interop:did-resolve:web:ebsi',
  ]);
  // 許可リストには `fixture-missing` で登録してあるが、変数が未設定だと `prerequisite-missing` が
  // 先に当たる。この「登録と違う理由」が運用前提の未充足を検知し続ける仕掛け。
  for (const line of errors) {
    assert.match(line, /登録と違う理由/);
    assert.match(line, /期待: fixture-missing/);
    assert.match(line, /実際: prerequisite-missing/);
  }
});

test('DID 解決マトリクスは EBSI_SANDBOX_BASE_URL を登録すれば厳格モードでも違反 0 件で通る', async () => {
  const { exitCode, violatedPairs } = await runDidResolutionMain(STRICT_ARGV, {
    EBSI_SANDBOX_BASE_URL: 'https://ebsi.test',
  });
  assert.deepEqual(violatedPairs, []);
  assert.equal(exitCode, 0);
});

test('DID 解決マトリクスは --fail-on-skipped が無ければ実設定でも終了コード 0', async () => {
  const { exitCode } = await runDidResolutionMain(PLAIN_ARGV, {});
  assert.equal(exitCode, 0);
});

test('Job Summary は件数の内訳と pass 以外のペア名・理由を出す', () => {
  const markdown = formatStatusSummary('Interop VC 発行・検証マトリクス', [
    { pair: 'interop:vericerts:vericerts', status: 'pass' },
    {
      pair: 'interop:ebsi:prerequisite',
      status: 'skipped',
      reason: 'prerequisite-missing: 環境変数 EBSI_SANDBOX_BASE_URL が未設定',
    },
    {
      pair: 'interop:vericerts:veramo',
      status: 'known-incompatible',
      reason: '[interop:vericerts:veramo] 既知',
    },
  ]);
  assert.match(markdown, /ペア数 3 件中: pass 1 \/ fail 0 \/ skipped 1 \/ known-incompatible 1/);
  assert.match(markdown, /interop:ebsi:prerequisite.*skipped.*prerequisite-missing/);
  assert.ok(!markdown.includes('interop:vericerts:vericerts'), 'pass のペアは表に出さない');
});

test('Job Summary は GITHUB_STEP_SUMMARY が無ければ何も書かない', () => {
  const written = [];
  const append = (file, text) => written.push([file, text]);
  assert.equal(appendJobSummary('x', {}, append), false);
  assert.equal(appendJobSummary('x', { GITHUB_STEP_SUMMARY: '' }, append), false);
  assert.equal(appendJobSummary('x', { GITHUB_STEP_SUMMARY: '/tmp/summary.md' }, append), true);
  assert.deepEqual(written, [['/tmp/summary.md', 'x']]);
});
