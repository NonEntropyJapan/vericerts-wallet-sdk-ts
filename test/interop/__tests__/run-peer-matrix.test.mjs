// test/interop/__tests__/run-peer-matrix.test.mjs
//
// `run-peer-matrix.mjs`（Nightly 用の全ペアマトリクス実行）の結果マッピング・pass/fail 判定
// ロジックの回帰テスト。実ピア（Docker）・walt.id（bun サブプロセス）は起動せず、
// `fetchImpl` / `spawnImpl` / `config` / `env` を差し替えて外部 I/O をモックする。実ピアとの実
// HTTP 通信は Docker の実ピアマトリクスで検査する。
//
// 実行方法: リポジトリルートから
//   node --test test/interop/__tests__/run-peer-matrix.test.mjs

import assert from 'node:assert/strict';
import test from 'node:test';
import {
  ADAPTER_ENTRY_CHECK_ERROR,
  BASE_CONFIG,
  happyRoutes,
  jsonResponse,
  NATIVE_FORMAT_INCOMPATIBLE,
  routedFetch,
  runWith,
  spawnStub,
  uniformVerify,
} from '../test-support/run-peer-matrix.fixtures.mjs';

test('全ピアが正常応答すると uniform×uniform / uniform→native / native 発行 / walt.id / 外部前提が期待どおりに写像される（native×uniform も実際に試行する）', async () => {
  const output = await runWith({});

  assert.match(output.generatedAt, /^\d{4}-\d{2}-\d{2}T/);
  assert.deepEqual(output.results, [
    { pair: 'interop:peerA:peerA', status: 'pass', reason: undefined },
    { pair: 'interop:peerA:peerB', status: 'pass', reason: undefined },
    { pair: 'interop:peerB:peerA', status: 'pass', reason: undefined },
    { pair: 'interop:peerB:peerB', status: 'pass', reason: undefined },
    { pair: 'interop:peerA:nativeA', status: 'pass', reason: undefined },
    { pair: 'interop:peerB:nativeA', status: 'pass', reason: undefined },
    { pair: 'interop:nativeA:nativeA', status: 'pass' },
    {
      pair: 'interop:nativeA:peerA',
      status: 'known-incompatible',
      reason: `#${NATIVE_FORMAT_INCOMPATIBLE[0].issue} ${NATIVE_FORMAT_INCOMPATIBLE[0].note} — HTTP 400: ${ADAPTER_ENTRY_CHECK_ERROR}`,
    },
    {
      pair: 'interop:nativeA:peerB',
      status: 'known-incompatible',
      reason: `#${NATIVE_FORMAT_INCOMPATIBLE[1].issue} ${NATIVE_FORMAT_INCOMPATIBLE[1].note} — HTTP 400: ${ADAPTER_ENTRY_CHECK_ERROR}`,
    },
    { pair: 'interop:waltid-issuer:vericerts', status: 'pass' },
    { pair: 'interop:vericerts:waltid-verifier', status: 'pass' },
    { pair: 'interop:ext:smoke', status: 'pass', reason: undefined },
  ]);
});

test('uniform ピアの発行失敗は、その issuer から全 verifier への pair を fail にする（すべて pass と誤判定しない）', async () => {
  const routes = happyRoutes();
  routes['POST http://peer-a.test/vc/issue'] = () => jsonResponse(500, { error: 'boom' });

  const output = await runWith({ fetchImpl: routedFetch(routes) });

  const fromA = output.results.filter((r) => r.pair.startsWith('interop:peerA:'));
  assert.deepEqual(
    fromA.map((r) => r.status),
    ['fail', 'fail', 'fail'],
  );
  // ステップ1（uniform×uniform）は Error.message、ステップ2（uniform→native）は例外自体を
  // String() 化した reason になる — 表現差はあるが、いずれも pass への誤判定は起きていない。
  assert.match(fromA[0].reason, /^issue failed: /);
  assert.match(fromA[1].reason, /^issue failed: /);
  assert.match(fromA[2].reason, /^Error: issue failed: /);
});

test('uniform 検証が verified=false を返すと fail、reason に検証エラーが伝播する', async () => {
  const routes = happyRoutes();
  routes['POST http://peer-b.test/vc/verify'] = () =>
    jsonResponse(200, { verified: false, error: 'signature invalid' });

  const output = await runWith({ fetchImpl: routedFetch(routes) });

  assert.deepEqual(
    output.results.find((r) => r.pair === 'interop:peerA:peerB'),
    {
      pair: 'interop:peerA:peerB',
      status: 'fail',
      reason: 'signature invalid',
    },
  );
});

test('uniform 検証呼び出しが例外を投げると fail になり、reason に例外内容が入る（すべて pass と誤判定しない）', async () => {
  const routes = happyRoutes();
  routes['POST http://peer-a.test/vc/verify'] = () => {
    throw new Error('network down');
  };

  const output = await runWith({ fetchImpl: routedFetch(routes) });

  const bToA = output.results.find((r) => r.pair === 'interop:peerB:peerA');
  assert.equal(bToA.status, 'fail');
  assert.match(bToA.reason, /network down/);
});

test('native ピアの検証が errors 配列（トップレベル配列 / { errors } の両形）を返した場合、fail かつ理由が結合される', async () => {
  const cases = [
    { body: ['ctx mismatch', 'issuer unknown'], reason: 'ctx mismatch; issuer unknown' },
    { body: { errors: ['missing public key'] }, reason: 'missing public key' },
  ];
  for (const { body, reason } of cases) {
    const routes = happyRoutes();
    routes['POST http://native-a.test/credentials/verify'] = () => jsonResponse(200, body);

    const output = await runWith({ fetchImpl: routedFetch(routes) });
    assert.deepEqual(
      output.results.find((r) => r.pair === 'interop:peerA:nativeA'),
      {
        pair: 'interop:peerA:nativeA',
        status: 'fail',
        reason,
      },
    );
  }
});

test('native ピアの発行が失敗すると自己ペアも uniform 2 ペアも fail で出す（known-incompatible に畳まず、黙って落とさない）', async () => {
  const routes = happyRoutes();
  routes['POST http://native-a.test/credentials/issue'] = () =>
    jsonResponse(500, { error: 'key not found' });

  const output = await runWith({ fetchImpl: routedFetch(routes) });

  const selfPairs = output.results.filter((r) => r.pair === 'interop:nativeA:nativeA');
  assert.equal(selfPairs.length, 1);
  assert.equal(selfPairs[0].status, 'fail');
  assert.match(selfPairs[0].reason, /^self-issue failed: /);

  const toUniform = output.results.filter((r) => r.pair.startsWith('interop:nativeA:peer'));
  assert.deepEqual(
    toUniform.map((r) => r.status),
    ['fail', 'fail'],
  );
  for (const result of toUniform) {
    assert.match(result.reason, /^issue failed: /);
  }
});

test('walt.id サブプロセスの起動失敗・出力なし・JSON 解釈不能は、いずれも両ペアを fail として報告する（サイレントに pass 扱いしない）', async () => {
  const cases = [
    {
      spawnResult: { error: new Error('spawn bun ENOENT'), stdout: '', stderr: '' },
      reason: /起動に失敗した.*spawn bun ENOENT/,
    },
    {
      spawnResult: { error: undefined, stdout: '', stderr: 'crashed' },
      reason: /標準出力を返さなかった.*crashed/,
    },
    {
      spawnResult: { error: undefined, stdout: 'not json', stderr: '' },
      reason: /JSON として解釈できなかった/,
    },
  ];
  for (const { spawnResult, reason } of cases) {
    const output = await runWith({ spawnImpl: spawnStub(spawnResult) });
    const waltid = output.results.filter((r) => r.pair.includes('waltid'));
    assert.deepEqual(
      waltid.map((r) => r.pair),
      ['interop:waltid-issuer:vericerts', 'interop:vericerts:waltid-verifier'],
    );
    for (const r of waltid) {
      assert.equal(r.status, 'fail');
      assert.match(r.reason, reason);
    }
  }
});

test('walt.id ドライバは compose ネットワーク内の one-off サービスとして実行し、管理系 baseUrl を -e で渡す', async () => {
  const calls = [];
  const spawnImpl = (cmd, args, opts) => {
    calls.push({ cmd, args, opts });
    return { error: undefined, stdout: JSON.stringify({ results: [] }), stderr: '' };
  };

  await runWith({ spawnImpl });

  assert.equal(calls.length, 1);
  assert.equal(calls[0].cmd, 'docker');
  const { args } = calls[0];
  assert.equal(args[0], 'compose');
  // 進捗が標準出力へ混ざるとドライバの JSON 出力が壊れる（`--progress quiet` が必要）。
  assert.deepEqual(args.slice(1, 3), ['--progress', 'quiet']);
  assert.ok(args.includes('run') && args.includes('--rm') && args.includes('--no-deps'));
  // ビルドは timeout（5 分）の外（workflow の別 step）で行う。run 側に `--build` を戻さない。
  assert.ok(!args.includes('--build'));
  assert.equal(args.at(-1), 'waltid-driver');
  assert.ok(args.includes('WALTID_ISSUER_ADMIN_BASE_URL=http://waltid-issuer.test'));
  assert.ok(args.includes('WALTID_VERIFIER_ADMIN_BASE_URL=http://waltid-verifier.test'));
});

test('外部前提（EBSI 等）は要求する環境変数が未設定なら skipped、外部前提ピアへの HTTP 呼び出しを一切行わない', async () => {
  let extFetchCalled = false;
  const output = await runWith({
    fetchImpl: async (url, options) => {
      if (url.startsWith('http://ext.test')) {
        extFetchCalled = true;
      }
      return routedFetch(happyRoutes())(url, options);
    },
    env: {},
  });

  assert.equal(extFetchCalled, false);
  assert.deepEqual(
    output.results.find((r) => r.pair === 'interop:ext:prerequisite'),
    {
      pair: 'interop:ext:prerequisite',
      status: 'skipped',
      reason: 'prerequisite-missing: 環境変数 EXT_SANDBOX_BASE_URL が未設定（test prerequisite）',
    },
  );
});

test('外部前提の環境変数はあるがピアが応答しない場合は fail（すべて pass と誤判定しない）', async () => {
  const routes = happyRoutes();
  routes['GET http://ext.test/'] = () => {
    throw new Error('connection refused');
  };

  const output = await runWith({ fetchImpl: routedFetch(routes) });

  assert.deepEqual(
    output.results.find((r) => r.pair === 'interop:ext:smoke'),
    {
      pair: 'interop:ext:smoke',
      status: 'fail',
      reason: 'ext プロキシが応答しなかった',
    },
  );
});

// ---- 既知の非互換（pairs.json の knownIncompatible）-------------------------

const KNOWN = {
  pair: 'interop:peerA:peerB',
  issue: 1,
  reasonIncludes: 'missing default context',
  note: 'peerA の context を peerB が受理しない',
};

const statusOf = (output, pair) => output.results.find((r) => r.pair === pair)?.status;

test('登録ペアが登録どおりの理由で落ちると known-incompatible になり、他の pass は変わらない', async () => {
  const routes = happyRoutes();
  // peerA 発行の JWT（`jwt-from-a`）だけを peerB が拒否する。peerB 発行の JWT は通す。
  routes['POST http://peer-b.test/vc/verify'] = uniformVerify((options) =>
    JSON.parse(options.body).jwt === 'jwt-from-a'
      ? jsonResponse(200, { verified: false, error: 'schema_error: missing default context "v1"' })
      : jsonResponse(200, { verified: true }),
  );

  const output = await runWith({
    config: { ...BASE_CONFIG, knownIncompatible: [...NATIVE_FORMAT_INCOMPATIBLE, KNOWN] },
    fetchImpl: routedFetch(routes),
  });

  assert.equal(statusOf(output, 'interop:peerA:peerB'), 'known-incompatible');
  assert.equal(statusOf(output, 'interop:peerA:peerA'), 'pass');
  assert.equal(output.results.filter((r) => r.status === 'fail').length, 0);
});

test('登録ペアが想定外に通ると fail になる（非互換の解消を検知する）', async () => {
  const output = await runWith({
    config: { ...BASE_CONFIG, knownIncompatible: [...NATIVE_FORMAT_INCOMPATIBLE, KNOWN] },
  });

  const result = output.results.find((r) => r.pair === 'interop:peerA:peerB');
  assert.equal(result.status, 'fail');
  assert.match(result.reason, /^unexpected-pass: /);
});

test('登録外のペアが落ちると、登録があっても fail のまま（新しく落ちたペアを検知する）', async () => {
  const routes = happyRoutes();
  routes['POST http://peer-b.test/vc/verify'] = () =>
    jsonResponse(200, { verified: false, error: 'missing default context' });
  routes['POST http://peer-a.test/vc/verify'] = () =>
    jsonResponse(200, { verified: false, error: 'missing default context' });

  const output = await runWith({
    config: { ...BASE_CONFIG, knownIncompatible: [...NATIVE_FORMAT_INCOMPATIBLE, KNOWN] },
    fetchImpl: routedFetch(routes),
  });

  assert.equal(statusOf(output, 'interop:peerA:peerB'), 'known-incompatible');
  assert.equal(statusOf(output, 'interop:peerB:peerB'), 'fail');
  assert.equal(statusOf(output, 'interop:peerB:peerA'), 'fail');
});
