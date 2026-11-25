// test/interop/__tests__/did-resolution/runner.test.mjs
//
// run-did-resolution-matrix.mjs を実設定（`pairs.json`）＋ fetch スタブで駆動し、
// 駆動できないペアが「理由の分かる skipped」として報告されることを固定する。
//
//   - walt.id は DID 解決の HTTP 経路を公開していない → resolver-unavailable
//   - EBSI は EBSI_SANDBOX_BASE_URL（運用側の前提）が未設定 → prerequisite-missing
//   - did:web / did:ethr / did:ebsi は fixture 未整備 → fixture-missing
//
// 理由を伴わない skipped や、skip 条件の優先順位の入れ替わり（EBSI が fixture-missing として
// 報告される等）は、前提が整った後も原因を誤らせるため、ここで固定する。
//
// 実行方法: リポジトリルートから
//   node --test test/interop/__tests__/did-resolution/runner.test.mjs

import assert from 'node:assert/strict';
import test from 'node:test';
import { run } from '../../run-did-resolution-matrix.mjs';
import { composePortStub, PAIRS, recordingFetch } from './fixtures.mjs';

const PAIR_COUNT = Object.values(PAIRS.didResolution.matrix).flat().length;

/** 実設定を fetch スタブで 1 回実行し、ペア名で引ける形にする。 */
async function runAll({ fetchImpl = recordingFetch(), env = {} } = {}) {
  const { results } = await run({ fetchImpl, spawnImpl: composePortStub(), env });
  return { results, byPair: Object.fromEntries(results.map((r) => [r.pair, r])) };
}

test('ランナーは公開 matrix 契約のペアをちょうど 18 件（matrix の総数）返す', async () => {
  const { results } = await runAll();
  assert.equal(results.length, PAIR_COUNT);
  assert.equal(PAIR_COUNT, 18);
});

test('walt.id のペアは resolver-unavailable の理由付きで skipped になる', async () => {
  const { results } = await runAll();
  const waltid = results.filter((r) => r.pair.endsWith(':waltid'));
  assert.equal(waltid.length, 4, 'walt.id のペア数が公開 matrix 契約と違う');
  for (const result of waltid) {
    assert.equal(result.status, 'skipped', result.pair);
    assert.match(result.reason, /^resolver-unavailable: /);
    assert.match(result.reason, /DID 解決の HTTP エンドポイントを公開しておらず/);
  }
});

test('EBSI のペアは EBSI_SANDBOX_BASE_URL 未設定なら prerequisite-missing で skipped になる', async () => {
  const { byPair } = await runAll();
  for (const pair of ['interop:did-resolve:web:ebsi', 'interop:did-resolve:ebsi:ebsi']) {
    assert.equal(byPair[pair].status, 'skipped', pair);
    assert.match(
      byPair[pair].reason,
      /^prerequisite-missing: 環境変数 EBSI_SANDBOX_BASE_URL が未設定/,
    );
  }
});

test('EBSI_SANDBOX_BASE_URL が設定されると prerequisite-missing では止まらず、次の判定（fixture-missing）へ進む', async () => {
  const { byPair } = await runAll({ env: { EBSI_SANDBOX_BASE_URL: 'https://ebsi.test' } });
  assert.match(byPair['interop:did-resolve:ebsi:ebsi'].reason, /^fixture-missing: /);
});

test('fixture 未整備のメソッド（did:web / did:ethr / did:ebsi）は fixture-missing で skipped になる', async () => {
  const { results } = await runAll();
  const fixtureMissing = results.filter(
    (r) =>
      r.pair.startsWith('interop:did-resolve:web:') ||
      r.pair.startsWith('interop:did-resolve:ethr:'),
  );
  for (const result of fixtureMissing) {
    // walt.id / EBSI は先に resolver-unavailable / prerequisite-missing で止まる（判定の優先順位）。
    if (result.pair.endsWith(':waltid') || result.pair.endsWith(':ebsi')) continue;
    assert.equal(result.status, 'skipped', result.pair);
    assert.match(result.reason, /^fixture-missing: /, result.pair);
  }
  assert.match(byReason(results, 'interop:did-resolve:ebsi:sphereon'), /^fixture-missing: /);
});

test('解決に成功したペアだけが pass になり、skipped のペアは解決要求を出さない', async () => {
  const fetchImpl = recordingFetch();
  const { results, byPair } = await runAll({ fetchImpl });
  const passed = results.filter((r) => r.status === 'pass').map((r) => r.pair);
  assert.deepEqual(passed.sort(), [
    'interop:did-resolve:jwk:sphereon',
    'interop:did-resolve:jwk:veramo',
    'interop:did-resolve:key:didkit',
    'interop:did-resolve:key:sphereon',
    'interop:did-resolve:key:veramo',
  ]);
  assert.equal(byPair['interop:did-resolve:key:sphereon'].reason, undefined);
  assert.equal(
    results.filter((r) => r.status === 'fail').length,
    0,
    '正常応答のみを返したのに fail が出た',
  );
  // 解決要求は駆動できる 5 ペア分だけ（skipped のペアが通信していないこと）。
  assert.equal(fetchImpl.requested.length, passed.length);
  assert.deepEqual([...new Set(fetchImpl.requested.map((did) => did.split(':')[1]))].sort(), [
    'jwk',
    'key',
  ]);
});

/** ペア名から理由を取り出す（存在しないペアはテストを落とす）。 */
function byReason(results, pair) {
  const found = results.find((r) => r.pair === pair);
  assert.ok(found, `${pair} が結果に無い`);
  return found.reason;
}
