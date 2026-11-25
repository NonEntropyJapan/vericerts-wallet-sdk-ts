// test/interop/__tests__/run-peer-matrix.robustness.test.mjs
//
// run-peer-matrix.mjs の結果記録の堅牢性の回帰テスト。
//   - uniform×native ループで後段 native の通信例外が前段 native の pass と
//     同一ペアに二重記録されない
//   - walt.id 子プロセスの出力が `{ results: PairResult[] }` でなくても matrix 全体が
//     TypeError で中断せず、timeout 付きで起動される
//   - walt.id の全ペアが skipped（公開ホスト検査へ退行）なら fail に倒す
//
// 実行方法: リポジトリルートから
//   node --test test/interop/__tests__/run-peer-matrix.robustness.test.mjs

import assert from 'node:assert/strict';
import test from 'node:test';
import {
  BASE_CONFIG,
  happyRoutes,
  jsonResponse,
  routedFetch,
  runWith,
  spawnStub,
} from '../test-support/run-peer-matrix.fixtures.mjs';

const WALTID_PAIRS = ['interop:waltid-issuer:vericerts', 'interop:vericerts:waltid-verifier'];

test('regression: 後段 native の通信例外は当該ペアだけ fail にし、前段 native の pass を二重記録しない', async () => {
  const config = {
    ...BASE_CONFIG,
    nativePeers: [
      ...BASE_CONFIG.nativePeers,
      {
        name: 'nativeB',
        baseUrl: 'http://native-b.test',
        kind: 'native-vc-api',
        issuerDid: 'did:example:native-b',
      },
    ],
  };
  const routes = {
    ...happyRoutes(),
    // nativeB の検証だけ fetch 例外（接続拒否相当）。nativeA は正常。
    'POST http://native-b.test/credentials/verify': () => {
      throw new TypeError('fetch failed');
    },
    'POST http://native-b.test/credentials/issue': () =>
      jsonResponse(201, { verifiableCredential: { proof: {} } }),
  };
  const output = await runWith({ config, fetchImpl: routedFetch(routes) });

  const pairs = output.results.map((r) => r.pair);
  assert.equal(new Set(pairs).size, pairs.length, `同一ペアの重複記録: ${pairs.join(', ')}`);
  const byPair = Object.fromEntries(output.results.map((r) => [r.pair, r]));
  for (const issuer of ['peerA', 'peerB']) {
    assert.equal(byPair[`interop:${issuer}:nativeA`].status, 'pass');
    assert.equal(byPair[`interop:${issuer}:nativeB`].status, 'fail');
    assert.match(byPair[`interop:${issuer}:nativeB`].reason, /fetch failed/);
  }
});

test('regression: walt.id 子プロセスの results が欠落・非配列・空・不正要素なら両ペア fail（TypeError で中断しない）', async () => {
  const outputs = [
    '{}',
    '{"results":null}',
    '{"results":"x"}',
    '{"results":[]}',
    '{"results":[{"pair":"p"}]}',
    '{"results":[null]}',
    'null',
  ];
  for (const stdout of outputs) {
    const output = await runWith({
      spawnImpl: spawnStub({ error: undefined, stdout, stderr: '' }),
    });
    const waltid = output.results.filter((r) => r.pair.includes('waltid'));
    assert.deepEqual(
      waltid.map((r) => r.pair),
      WALTID_PAIRS,
      stdout,
    );
    for (const r of waltid) {
      assert.equal(r.status, 'fail', stdout);
      assert.match(r.reason, /results: PairResult\[\]/, stdout);
    }
    // それまでのペア結果は捨てられず、後続の外部前提チェックまで走る。
    assert.ok(
      output.results.some((r) => r.pair === 'interop:peerA:peerB'),
      stdout,
    );
    assert.ok(
      output.results.some((r) => r.pair === 'interop:ext:smoke'),
      stdout,
    );
  }
});

test('regression: walt.id 子プロセスは timeout 付きで起動し、timeout 超過（proc.error）は両ペア fail にする', async () => {
  let spawnOptions;
  const output = await runWith({
    spawnImpl: (_cmd, _args, options) => {
      spawnOptions ??= options; // 2 回目以降は孤児コンテナ掃除（docker rm）なので、起動時の options を見る
      return { error: new Error('spawnSync bun ETIMEDOUT'), stdout: '', stderr: '' };
    },
  });
  assert.ok(Number.isFinite(spawnOptions.timeout) && spawnOptions.timeout > 0);
  assert.equal(spawnOptions.killSignal, 'SIGKILL');
  const waltid = output.results.filter((r) => r.pair.includes('waltid'));
  assert.deepEqual(
    waltid.map((r) => r.status),
    ['fail', 'fail'],
  );
  assert.match(waltid[0].reason, /ETIMEDOUT/);
});

test('walt.id の全ペアが skipped（公開ホスト検査へ退行し実駆動されない）なら、両ペアを fail に倒して Nightly に検知させる', async () => {
  const output = await runWith({
    spawnImpl: spawnStub({
      error: undefined,
      stdout: JSON.stringify({
        results: [
          { pair: 'interop:waltid-issuer:vericerts', status: 'skipped', reason: 'guard' },
          { pair: 'interop:vericerts:waltid-verifier', status: 'skipped', reason: 'no vc' },
        ],
      }),
      stderr: '',
    }),
  });
  const waltid = output.results.filter((r) => r.pair.includes('waltid'));
  assert.deepEqual(
    waltid.map((r) => r.status),
    ['fail', 'fail'],
  );
  assert.match(waltid[0].reason, /全ペアが skipped/);
});

test('regression: 子プロセスを実駆動できず両ペアを同じ理由で fail にする経路でも、verifier を issuer の巻き添えとして畳む', async () => {
  // `failBoth` は 2 ペアに**同じ理由**を載せるため、`causedBy` が無いと起票側が同根と判定できず、
  // 同じ原因の Issue が 2 件立つ。起動失敗・出力欠落・JSON 不正・形式不正・
  // 全ペア skipped のどれでも同じ形で返ることを固定する。
  const [issuerPair, verifierPair] = WALTID_PAIRS;
  const cases = {
    '起動失敗（proc.error）': { error: new Error('spawn docker ENOENT'), stdout: '', stderr: '' },
    標準出力が空: { error: undefined, stdout: '', stderr: 'boom' },
    'JSON として解釈できない': { error: undefined, stdout: 'not json', stderr: '' },
    '{ results: PairResult[] } 形式ではない': { error: undefined, stdout: '{}', stderr: '' },
    '全ペア skipped': {
      error: undefined,
      stdout: JSON.stringify({
        results: [
          { pair: issuerPair, status: 'skipped', reason: 'guard' },
          { pair: verifierPair, status: 'skipped', reason: 'no vc' },
        ],
      }),
      stderr: '',
    },
  };
  for (const [label, proc] of Object.entries(cases)) {
    const output = await runWith({ spawnImpl: spawnStub(proc) });
    const waltid = output.results.filter((r) => r.pair.includes('waltid'));
    assert.deepEqual(
      waltid.map((r) => r.status),
      ['fail', 'fail'],
      label,
    );
    assert.equal(waltid[0].causedBy, undefined, `${label}: 元のペアに causedBy が付いている`);
    assert.equal(waltid[1].causedBy, issuerPair, label);
  }
});

test('walt.id の一方だけが skipped でも（もう一方が実駆動された）そのまま報告する', async () => {
  const output = await runWith({
    spawnImpl: spawnStub({
      error: undefined,
      stdout: JSON.stringify({
        results: [
          { pair: 'interop:waltid-issuer:vericerts', status: 'pass' },
          { pair: 'interop:vericerts:waltid-verifier', status: 'skipped', reason: 'x' },
        ],
      }),
      stderr: '',
    }),
  });
  const waltid = output.results.filter((r) => r.pair.includes('waltid'));
  assert.deepEqual(
    waltid.map((r) => r.status),
    ['pass', 'skipped'],
  );
});
