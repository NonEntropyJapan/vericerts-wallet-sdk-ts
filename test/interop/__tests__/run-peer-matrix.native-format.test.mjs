// test/interop/__tests__/run-peer-matrix.native-format.test.mjs
//
// native 発行（LD-Proof）× uniform 検証の 4 ペアを、決め打ちの `skipped` ではなく**実際に試行**し、
// `pairs.json` の `knownIncompatible` で扱うことの回帰テスト。
//
// ここで固定するのは「`reasonIncludes` が原因を区別できる」こと —— 登録どおりの理由の fail だけが
// `known-incompatible` に畳まれ、別原因（発行失敗 / 接続失敗 / HTTP 5xx / `error` の無い応答 /
// 検証器が評価したうえでの別の拒否理由）は `fail` のまま残る。`interop:veramo:vericerts` の
// `reasonIncludes: "3002"` だけだと、別の原因の失敗まで既知扱いにしてしまう。
//
// 実行方法: node --test test/interop/__tests__/run-peer-matrix.native-format.test.mjs

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import {
  ENTRY_CHECK_ERROR,
  NATIVE_UNIFORM_PAIRS,
  PAIRS,
  statusesOfNativeUniformPairs,
} from '../test-support/native-uniform-scenario.mjs';
import { jsonResponse, textResponse } from '../test-support/run-peer-matrix.fixtures.mjs';

const CONTRACT = JSON.parse(
  readFileSync(new URL('../contracts/matrix.json', import.meta.url), 'utf8'),
);

test('4 ペアは pairs.json の knownIncompatible に公開ペアIDで登録され、理由が原因を区別できる文言になっている', () => {
  for (const pair of NATIVE_UNIFORM_PAIRS) {
    const entry = PAIRS.knownIncompatible.find((e) => e.pair === pair);
    assert.ok(entry, `${pair} が knownIncompatible に無い`);
    assert.equal(entry.reasonIncludes, ENTRY_CHECK_ERROR);
    assert.equal(Object.hasOwn(entry, 'issue'), false, pair);
    assert.deepEqual(
      CONTRACT.vc.knownIncompatible.filter((item) => item.pair === pair),
      [entry],
    );
    // `3002` のような広い数値コードや短い断片を使わない。
    assert.ok(entry.reasonIncludes.length >= 16, `${pair}: reasonIncludes が短すぎる`);
  }
  // VC マトリクス側に構造的な skipped の許可リストは残していない。
  assert.equal(PAIRS.structuralSkips, undefined);
});

test('登録どおりの理由（アダプタの入口検査の 400）で落ちた 4 ペアは known-incompatible になる', async () => {
  const results = await statusesOfNativeUniformPairs({
    uniformVerify: () => jsonResponse(400, { verified: false, error: ENTRY_CHECK_ERROR }),
  });
  for (const result of results) {
    assert.equal(result.status, 'known-incompatible', result.pair);
    assert.ok(result.reason.startsWith(`[${result.pair}] `), result.pair);
    // fail-closed の `HTTP <status>: ` 接頭辞が付いても `reasonIncludes` の部分一致は維持される。
    assert.match(result.reason, /HTTP 400: /, result.pair);
    assert.ok(result.reason.includes(ENTRY_CHECK_ERROR), result.pair);
  }
});

test('登録ペアが通ってしまったら unexpected-pass の fail にする（アダプタが LD-Proof を受理し始めた合図）', async () => {
  const results = await statusesOfNativeUniformPairs({
    uniformVerify: () => jsonResponse(200, { verified: true }),
  });
  for (const result of results) {
    assert.equal(result.status, 'fail', result.pair);
    assert.match(result.reason, /^unexpected-pass: /);
  }
});

test('別原因の失敗は known-incompatible に畳まれず fail のまま残る（reasonIncludes が原因を区別できる）', async () => {
  const cases = [
    {
      name: '接続失敗・タイムアウト',
      overrides: {
        uniformVerify: () => {
          throw new TypeError('fetch failed');
        },
      },
      reason: /fetch failed/,
    },
    {
      name: 'HTTP 5xx（本文が JSON でない）',
      overrides: { uniformVerify: () => textResponse(502, '<html>Bad Gateway</html>') },
      // プロキシ/アダプタのダウンは「検証器が評価して拒否した」と読めない文言で残す。
      reason: /HTTP 502/,
    },
    {
      name: 'error を持たない応答',
      overrides: { uniformVerify: () => jsonResponse(200, { verified: false }) },
      reason: /検証が verified=false を返した/,
    },
    {
      name: '検証器が評価したうえでの別の拒否理由',
      overrides: {
        uniformVerify: () =>
          jsonResponse(200, { verified: false, error: '3002: VC の必須属性に違反しています' }),
      },
      reason: /3002/,
    },
  ];
  for (const { name, overrides, reason } of cases) {
    const results = await statusesOfNativeUniformPairs(overrides);
    for (const result of results) {
      assert.equal(result.status, 'fail', `${name} / ${result.pair}`);
      assert.match(result.reason, reason, `${name} / ${result.pair}`);
    }
  }
});

test('native ピアの発行が失敗したときも 4 ペアは fail で出る（known-incompatible に畳まれない）', async () => {
  const results = await statusesOfNativeUniformPairs({
    uniformVerify: () => jsonResponse(400, { verified: false, error: ENTRY_CHECK_ERROR }),
    nativeIssue: () => jsonResponse(500, { error: 'key not found' }),
  });
  for (const result of results) {
    assert.equal(result.status, 'fail', result.pair);
    assert.match(result.reason, /^issue failed: /);
  }
});
