// test/interop/__tests__/did-resolution/ethr-versions.test.mjs
//
// did:ethr の EIP-1056 複数版の扱いの回帰テスト。
//
// ここで固定するのは「単一の固定版が通っただけでは複数版対応と見なさない」こと。1 版しか叩かずに
// pass にすると、マトリクスの did:ethr セルが通っていても古い版だけを検証し続けることになる。
// そのため、実際に要求された DID を記録する fetch スタブで「全版を叩いたか」まで検査する。
//
// 実行方法: リポジトリルートから
//   node --test test/interop/__tests__/did-resolution/ethr-versions.test.mjs

import assert from 'node:assert/strict';
import test from 'node:test';
import {
  ethrConfig,
  jsonResponse,
  recordingFetch,
  resolutionResultFor,
  runSinglePair,
} from './fixtures.mjs';

const LEGACY = {
  version: 'eip1056-registry-0xdca7ef03',
  registry: '0xdca7ef03e98e0dc2b855be647c39abe984fcf21b',
  did: 'did:ethr:0x1:0xb9c5714089478a327f09197987f16f9e5d936e8a',
};

const CURRENT = {
  version: 'eip1056-registry-0x03d5003b',
  registry: '0x03d5003bf0e79c5f5223588f347eba39afbc3818',
  did: 'did:ethr:0xaa36a7:0xb9c5714089478a327f09197987f16f9e5d936e8a',
};

const unavailable = (version, reason) => ({ ...version, unavailable: reason });

test('全 EIP-1056 版が解決できたときだけ pass になり、全版の DID が実際に要求される', async () => {
  const fetchImpl = recordingFetch();
  const result = await runSinglePair(fetchImpl, ethrConfig([LEGACY, CURRENT]));
  assert.equal(result.status, 'pass');
  assert.deepEqual(fetchImpl.requested, [LEGACY.did, CURRENT.did]);
});

test('1 版でも解決に失敗したら fail になり、失敗した版の識別子と理由が載る（成功した版では pass にしない）', async () => {
  const fetchImpl = recordingFetch((did) =>
    did === CURRENT.did
      ? jsonResponse(200, { didResolutionMetadata: { error: 'notFound' } })
      : jsonResponse(200, resolutionResultFor(did)),
  );
  const result = await runSinglePair(fetchImpl, ethrConfig([LEGACY, CURRENT]));
  assert.equal(result.status, 'fail');
  assert.match(result.reason, /^eip1056-version-failed: /);
  assert.ok(result.reason.includes(CURRENT.version), '失敗した版の識別子が理由に無い');
  assert.match(result.reason, /notFound/);
  assert.ok(!result.reason.includes(LEGACY.version), '成功した版まで失敗として報告している');
  // 片方が落ちても残りの版を飛ばさない（全版の結果を 1 回の実行で集める）。
  assert.deepEqual(fetchImpl.requested, [LEGACY.did, CURRENT.did]);
});

test('新しい版だけを解決して古い版を叩かない実装は pass にならない（複数版対応の形骸化を検知）', async () => {
  // 古い版の registry を知らないピア（当該 DID を解決できない）を模す。
  const fetchImpl = recordingFetch((did) =>
    did === LEGACY.did
      ? jsonResponse(200, { didResolutionMetadata: { error: 'unsupportedDidMethod' } })
      : jsonResponse(200, resolutionResultFor(did)),
  );
  const result = await runSinglePair(fetchImpl, ethrConfig([LEGACY, CURRENT]));
  assert.notEqual(result.status, 'pass');
  assert.equal(result.status, 'fail');
  assert.ok(result.reason.includes(LEGACY.version), '落ちた古い版が理由に無い');
});

test('全版が fixture 未整備なら skipped になり、版ごとの理由が載る', async () => {
  const fetchImpl = recordingFetch();
  const result = await runSinglePair(
    fetchImpl,
    ethrConfig([
      unavailable(LEGACY, 'チェーン fixture が harness に無い'),
      unavailable(CURRENT, '新しいチェーン向け registry の fixture が無い'),
    ]),
  );
  assert.equal(result.status, 'skipped');
  assert.match(result.reason, /^fixture-missing: /);
  for (const version of [LEGACY, CURRENT]) {
    assert.ok(result.reason.includes(version.version), `${version.version} の理由が無い`);
  }
  assert.match(result.reason, /チェーン fixture が harness に無い/);
  assert.deepEqual(fetchImpl.requested, [], 'fixture 未整備なのに解決を要求している');
});

test('一部の版だけ fixture 未整備なら skipped ではなく fail になる（未検証の版を黙って飛ばさない）', async () => {
  const result = await runSinglePair(
    recordingFetch(),
    ethrConfig([unavailable(LEGACY, 'チェーン fixture が無い'), CURRENT]),
  );
  assert.equal(result.status, 'fail');
  assert.ok(result.reason.includes(LEGACY.version));
  assert.match(result.reason, /fixture-missing/);
});

test('版が 1 つも定義されていない設定は pass にならず fail になる', async () => {
  const result = await runSinglePair(recordingFetch(), ethrConfig([]));
  assert.equal(result.status, 'fail');
  assert.match(result.reason, /^fixture-invalid: /);
});
