// test/interop/__tests__/run-internal-loop.test.mjs
//
// `run-internal-loop.mjs`（PR ゲート用の内部ループ）の駆動ロジック（引数解釈・期待結果判定）
// を検証する。大半のケースは `issueCredential` / `createPrivateKeySigner` /
// `verifyCredential` をスタブに差し替え、`run()` の判定ロジックだけを対象にする
// （`run-peer-matrix.test.mjs` が `fetchImpl`/`spawnImpl` をスタブにするのと同じ方針）。
// 正常系のみ、実 SDK 関数を差し替えずに end-to-end のラウンドトリップも検証する。
//
// パッケージをインストールした consumer で実行する（README 参照）。
//   bun test test/interop/__tests__/run-internal-loop.test.mjs

import assert from 'node:assert/strict';
import test from 'node:test';
import { reportAndExit, run } from '../run-internal-loop.mjs';

const FIXED_NOW = new Date('2026-01-01T00:00:00Z');
const FIXED_SEED = new Uint8Array(32).fill(7);

/** スタブ一式を組み立てる。`issueCredential` が受け取った `vc` を捕捉し、後段の `verifyCredential`
 * スタブが `iss` を計算する材料に使う（判定対象の `vc.issuer` 文字列をテスト側に複製しないため）。
 */
function stubs({ verifiedIssuer = (vc) => vc.issuer } = {}) {
  const calls = { createPrivateKeySigner: [], issueCredential: [], verifyCredential: [] };
  let capturedVc;

  const createPrivateKeySigner = (seed, alg) => {
    calls.createPrivateKeySigner.push([seed, alg]);
    return { publicKeyJwk: { kty: 'OKP', crv: 'Ed25519', x: 'stub-public-key' } };
  };

  const issueCredential = (vc, signer, opts) => {
    calls.issueCredential.push([vc, signer, opts]);
    capturedVc = vc;
    return 'stub.jwt.token';
  };

  const verifyCredential = (jwt, opts) => {
    calls.verifyCredential.push([jwt, opts]);
    return { payload: { iss: verifiedIssuer(capturedVc) } };
  };

  return { calls, createPrivateKeySigner, issueCredential, verifyCredential };
}

test('正常系: 発行した VC の issuer と検証結果の iss が一致すると ok:true を返す', () => {
  const { calls, createPrivateKeySigner, issueCredential, verifyCredential } = stubs();

  const result = run({
    createPrivateKeySigner,
    issueCredential,
    verifyCredential,
    now: FIXED_NOW,
    randomSeed: FIXED_SEED,
  });

  assert.equal(result.ok, true);
  assert.equal(result.message, 'internal loop OK: issue -> verify round trip succeeded');
  assert.equal(calls.createPrivateKeySigner.length, 1);
  assert.equal(calls.issueCredential.length, 1);
  assert.equal(calls.verifyCredential.length, 1);
});

test('引数解釈: createPrivateKeySigner にシードと EdDSA アルゴリズムが渡る', () => {
  const { calls, createPrivateKeySigner, issueCredential, verifyCredential } = stubs();

  run({
    createPrivateKeySigner,
    issueCredential,
    verifyCredential,
    now: FIXED_NOW,
    randomSeed: FIXED_SEED,
  });

  const [[seed, alg]] = calls.createPrivateKeySigner;
  assert.equal(seed, FIXED_SEED);
  assert.equal(alg, 'EdDSA');
});

test('引数解釈: issueCredential に issuer 付き VC と nowSeconds（now から算出）が渡る', () => {
  const { calls, createPrivateKeySigner, issueCredential, verifyCredential } = stubs();

  run({
    createPrivateKeySigner,
    issueCredential,
    verifyCredential,
    now: FIXED_NOW,
    randomSeed: FIXED_SEED,
  });

  const [[vc, , opts]] = calls.issueCredential;
  assert.equal(vc.issuer, 'did:example:interop-internal-loop');
  assert.equal(opts.nowSeconds, Math.floor(FIXED_NOW.getTime() / 1000));
});

test('引数解釈: verifyCredential に発行した jwt と signer の publicKeyJwk が渡る', () => {
  const { calls, createPrivateKeySigner, issueCredential, verifyCredential } = stubs();

  run({
    createPrivateKeySigner,
    issueCredential,
    verifyCredential,
    now: FIXED_NOW,
    randomSeed: FIXED_SEED,
  });

  const [[jwt, opts]] = calls.verifyCredential;
  assert.equal(jwt, 'stub.jwt.token');
  assert.deepEqual(opts.key.publicKeyJwk, { kty: 'OKP', crv: 'Ed25519', x: 'stub-public-key' });
});

test('異常系: 検証結果の iss が発行時の issuer と異なると ok:false になり、両方の値を報告する', () => {
  const { createPrivateKeySigner, issueCredential, verifyCredential } = stubs({
    verifiedIssuer: () => 'did:example:someone-else',
  });

  const result = run({
    createPrivateKeySigner,
    issueCredential,
    verifyCredential,
    now: FIXED_NOW,
    randomSeed: FIXED_SEED,
  });

  assert.equal(result.ok, false);
  assert.match(result.message, /issuer mismatch/);
  assert.match(result.message, /did:example:someone-else/);
  assert.match(result.message, /did:example:interop-internal-loop/);
});

test('reportAndExit: ok:true では exit を呼ばず message を log する', () => {
  const logged = [];
  const exited = [];

  reportAndExit(
    { ok: true, message: 'ok message' },
    {
      log: (m) => logged.push(m),
      error: () => assert.fail('error は呼ばれないはず'),
      exit: (code) => exited.push(code),
    },
  );

  assert.deepEqual(logged, ['ok message']);
  assert.deepEqual(exited, []);
});

test('reportAndExit: ok:false では message を error に出し、非0（1）で終了する（判定ロジックが常に成功扱いする退行を検出）', () => {
  const errored = [];
  const exited = [];

  reportAndExit(
    { ok: false, message: 'fail message' },
    {
      log: () => assert.fail('log は呼ばれないはず'),
      error: (m) => errored.push(m),
      exit: (code) => exited.push(code),
    },
  );

  assert.deepEqual(errored, ['fail message']);
  assert.deepEqual(exited, [1]);
});

test('end-to-end: 実 SDK 関数（スタブ無し）で発行 -> 検証ラウンドトリップが成功する', () => {
  const result = run({ now: FIXED_NOW, randomSeed: FIXED_SEED });

  assert.equal(result.ok, true);
  assert.equal(result.message, 'internal loop OK: issue -> verify round trip succeeded');
});
