// test/interop/__tests__/known-incompatible.test.mjs
//
// `lib/known-incompatible.mjs`（pairs.json の `knownIncompatible` を結果へ適用する）の回帰テスト
// 既知の非互換をマトリクスの fail にしない一方で、新しく落ちたペア・
// 想定外に通ったペア・登録と別の理由で落ちたペアは fail のまま検知し続けることを固定する。
//
// 実行方法: リポジトリルートから
//   node --test test/interop/__tests__/known-incompatible.test.mjs

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { applyKnownIncompatible, KNOWN_INCOMPATIBLE } from '../lib/known-incompatible.mjs';

const ENTRY = {
  pair: 'interop:a:b',
  issue: 1,
  reasonIncludes: 'missing default context',
  note: 'a の v2 context を b が受理しない',
};
const PUBLIC_CONFIG = JSON.parse(readFileSync(new URL('../pairs.json', import.meta.url), 'utf8'));
const CONTRACT = JSON.parse(
  readFileSync(new URL('../contracts/matrix.json', import.meta.url), 'utf8'),
);

test('登録ペアが登録どおりの理由で fail すると known-incompatible になり、Issue 番号と元の理由を残す', () => {
  const [result] = applyKnownIncompatible(
    [
      {
        pair: 'interop:a:b',
        status: 'fail',
        reason: 'schema_error: @context is missing default context "x"',
      },
    ],
    [ENTRY],
  );
  assert.equal(result.status, KNOWN_INCOMPATIBLE);
  assert.ok(result.reason.includes(`#${ENTRY.issue} `));
  assert.match(result.reason, /@context is missing default context "x"/);
});

test('登録ペアが pass すると fail（unexpected-pass）になる — 非互換の解消を黙って見逃さない', () => {
  const [result] = applyKnownIncompatible([{ pair: 'interop:a:b', status: 'pass' }], [ENTRY]);
  assert.equal(result.status, 'fail');
  assert.match(result.reason, /^unexpected-pass: /);
  assert.ok(result.reason.includes(`#${ENTRY.issue}`));
});

test('登録ペアが登録と別の理由で fail すると fail のまま（新しい壊れ方を既知の非互換に隠さない）', () => {
  const input = { pair: 'interop:a:b', status: 'fail', reason: 'ECONNREFUSED' };
  assert.deepEqual(applyKnownIncompatible([input], [ENTRY]), [input]);
});

test('登録ペアの reason が無い fail も known-incompatible にはならない', () => {
  const input = { pair: 'interop:a:b', status: 'fail' };
  assert.deepEqual(applyKnownIncompatible([input], [ENTRY]), [input]);
});

test('登録外のペアは結果を変えない（新しく落ちたペアは fail のまま）', () => {
  const results = [
    { pair: 'interop:c:d', status: 'fail', reason: 'missing default context' },
    { pair: 'interop:e:f', status: 'pass' },
    { pair: 'interop:g:h', status: 'skipped', reason: 'x' },
  ];
  assert.deepEqual(applyKnownIncompatible(results, [ENTRY]), results);
});

test('登録ペアの skipped は変えない', () => {
  const input = { pair: 'interop:a:b', status: 'skipped', reason: 'x' };
  assert.deepEqual(applyKnownIncompatible([input], [ENTRY]), [input]);
});

test('登録が無い / 省略のときは何も変えない', () => {
  const results = [{ pair: 'interop:a:b', status: 'fail', reason: 'missing default context' }];
  assert.deepEqual(applyKnownIncompatible(results), results);
  assert.deepEqual(applyKnownIncompatible(results, []), results);
});

test('入力の結果配列を変更しない', () => {
  const input = { pair: 'interop:a:b', status: 'fail', reason: 'missing default context' };
  applyKnownIncompatible([input], [ENTRY]);
  assert.deepEqual(input, {
    pair: 'interop:a:b',
    status: 'fail',
    reason: 'missing default context',
  });
});

test('不正な登録（空の reasonIncludes / issue が正の整数でない / 二重登録）は例外にする', () => {
  const results = [{ pair: 'interop:a:b', status: 'fail', reason: 'x' }];
  // 空文字の reasonIncludes は全理由に一致し、あらゆる fail を既知の非互換へ変えてしまう。
  assert.throws(
    () => applyKnownIncompatible(results, [{ ...ENTRY, reasonIncludes: '' }]),
    /reasonIncludes/,
  );
  assert.throws(() => applyKnownIncompatible(results, [{ ...ENTRY, issue: '1' }]), /issue/);
  assert.throws(() => applyKnownIncompatible(results, [{ ...ENTRY, issue: 0 }]), /issue/);
  assert.throws(() => applyKnownIncompatible(results, [ENTRY, ENTRY]), /二重/);
});

test('pairs.json の knownIncompatible は全件が有効な形式で、実在するペアだけを指す', () => {
  const config = PUBLIC_CONFIG;
  const uniform = config.uniformPeers.map((p) => p.name);
  const native = config.nativePeers.map((p) => p.name);
  // uniform 発行のペア（uniform×uniform と uniform→native）、native 発行 × uniform 検証のペア、
  // walt.id のプロトコル層 2 ペア
  // （`run-waltid-protocol.mjs` が報告する。実駆動で fail しうる）だけが `fail` を取りうる。
  const { issuer, verifier } = config.waltidProtocolPeers;
  const reachable = new Set([
    ...uniform.flatMap((issuerName) =>
      [...uniform, ...native].map((v) => `interop:${issuerName}:${v}`),
    ),
    ...native.flatMap((issuerName) => uniform.map((v) => `interop:${issuerName}:${v}`)),
    `interop:${issuer.name}:vericerts`,
    `interop:vericerts:${verifier.name}`,
  ]);

  assert.ok(Array.isArray(config.knownIncompatible));
  // 形式検証は applyKnownIncompatible が例外にする。
  applyKnownIncompatible([], config.knownIncompatible);
  for (const entry of config.knownIncompatible) {
    assert.equal(Object.hasOwn(entry, 'issue'), false);
    assert.ok(reachable.has(entry.pair), `${entry.pair} はマトリクスに存在しない（typo か改名）`);
  }
});

test('walt.id: 2 ペアとも登録外（失敗は fail のまま）', () => {
  const config = PUBLIC_CONFIG;
  // issuer 側は SDK 修正で pass になった。再び署名検証で落ちても known-incompatible に隠さない。
  // verifier 側は `presentation_submission` を送るようになって pass になった。再び 400 になっても隠さない。
  const results = applyKnownIncompatible(
    [
      { pair: 'interop:waltid-issuer:vericerts', status: 'pass' },
      {
        pair: 'interop:waltid-issuer:vericerts',
        status: 'fail',
        reason: 'VC / VP の署名検証に失敗しました',
      },
      { pair: 'interop:vericerts:waltid-verifier', status: 'pass' },
      {
        pair: 'interop:vericerts:waltid-verifier',
        status: 'fail',
        reason: 'VP Token の送信に失敗しました (HTTP 400)',
      },
    ],
    config.knownIncompatible,
  );
  assert.deepEqual(
    results.map((r) => r.status),
    ['pass', 'fail', 'pass', 'fail'],
  );
});

test('公開7登録はissue無しでpair参照と元の理由を保持する', () => {
  for (const entry of PUBLIC_CONFIG.knownIncompatible) {
    const reason = `検証失敗: ${entry.reasonIncludes}`;
    const input = { pair: entry.pair, status: 'fail', reason };
    assert.deepEqual(applyKnownIncompatible([input], [entry]), [
      {
        pair: entry.pair,
        status: KNOWN_INCOMPATIBLE,
        reason: `[${entry.pair}] ${entry.note} — ${reason}`,
      },
    ]);
    assert.deepEqual(input, { pair: entry.pair, status: 'fail', reason });
  }
});

test('公開登録のunexpected-pass・理由不一致・理由欠落・skippedを従来どおり検知する', () => {
  for (const entry of PUBLIC_CONFIG.knownIncompatible) {
    const { pair } = entry;
    const mismatch = { pair, status: 'fail', reason: 'ECONNREFUSED' };
    const noReason = { pair, status: 'fail' };
    const skipped = { pair, status: 'skipped', reason: entry.reasonIncludes };
    assert.deepEqual(
      applyKnownIncompatible([{ pair, status: 'pass' }, mismatch, noReason, skipped], [entry]),
      [
        {
          pair,
          status: 'fail',
          reason: `unexpected-pass: 既知の非互換（[${pair}]: ${entry.note}）のペアが通った。非互換が解消した可能性があるため、pairs.json の knownIncompatible から外すか理由を見直す`,
        },
        mismatch,
        noReason,
        skipped,
      ],
    );
  }
});

test('明示された不正なlegacy issueをpair参照へfallbackしない', () => {
  for (const issue of [undefined, null, '1', 0, -1, 1.5]) {
    assert.throws(() => applyKnownIncompatible([], [{ ...ENTRY, issue }]), /issue は正の整数/);
  }
});

test('公開defaultはprivate資料識別子やprivate mappingを前提にしない', () => {
  const entries = PUBLIC_CONFIG.knownIncompatible;
  assert.equal(entries.length, 7);
  assert.deepEqual(entries, CONTRACT.vc.knownIncompatible);
  const uniform = PUBLIC_CONFIG.uniformPeers.map(({ name }) => name);
  const native = PUBLIC_CONFIG.nativePeers.map(({ name }) => name);
  const pairs = [
    ...uniform.flatMap((issuer) => [...uniform, ...native].map((v) => `interop:${issuer}:${v}`)),
    ...native.flatMap((issuer) => [issuer, ...uniform].map((v) => `interop:${issuer}:${v}`)),
  ];
  assert.deepEqual(pairs.sort(), [...CONTRACT.vc.pairs].sort());
  assert.deepEqual(PUBLIC_CONFIG.structuralSkips ?? [], CONTRACT.vc.structuralSkips);
  for (const { pair, ...fields } of entries) {
    assert.match(pair, /^interop:[a-z]+:[a-z]+$/);
    assert.deepEqual(Object.keys(fields), ['reasonIncludes', 'note']);
    assert.ok(CONTRACT.vc.pairs.includes(pair));
  }
});
