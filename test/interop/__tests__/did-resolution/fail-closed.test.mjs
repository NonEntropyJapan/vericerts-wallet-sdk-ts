// test/interop/__tests__/did-resolution/fail-closed.test.mjs
//
// DID 解決ランナーの fail-closed の回帰テスト。
//
// ここで固定するのは「解決できていないのに pass にしない」こと。ピア未起動・タイムアウト・
// 5xx の HTML・別の DID を返す応答・検証鍵の無い DID Document を pass（または skipped）に
// してしまうと、Nightly が実質何も検証しないまま緑になり、外部ピアの退行を取り逃す。
//
// 実行方法: リポジトリルートから
//   node --test test/interop/__tests__/did-resolution/fail-closed.test.mjs

import assert from 'node:assert/strict';
import test from 'node:test';
import {
  didDocumentFor,
  jsonResponse,
  KEY_FIXTURE,
  PAIRS,
  recordingFetch,
  resolutionResultFor,
  runSinglePair,
  SINGLE_PAIR_DID,
  singleFixtureConfig,
  textResponse,
} from './fixtures.mjs';

/** 応答を返さず例外を投げる fetch スタブ（通信失敗の再現）。 */
const throwingFetch = (error) => async () => {
  throw error;
};

/** 正常な DID Document を部分的に壊した Resolution Result を返す。 */
function brokenDocument(patch) {
  const result = resolutionResultFor(SINGLE_PAIR_DID);
  return jsonResponse(200, { ...result, didDocument: { ...result.didDocument, ...patch } });
}

test('ピア未起動（fetch が ECONNREFUSED で例外）は pass にならず fail になり、接続先と原因が理由に残る', async () => {
  // undici は原因を `cause` に包む。localhost は IPv4/IPv6 の両方を試すため message 空の
  // AggregateError になることがあり、その場合も ECONNREFUSED を理由に出す必要がある。
  const causes = [
    new Error('connect ECONNREFUSED 127.0.0.1:8092'),
    Object.assign(new AggregateError([{ code: 'ECONNREFUSED' }, { code: 'ECONNREFUSED' }], ''), {
      code: 'ECONNREFUSED',
    }),
    new AggregateError([{ code: 'ECONNREFUSED' }], ''),
  ];
  for (const cause of causes) {
    const result = await runSinglePair(throwingFetch(new TypeError('fetch failed', { cause })));
    assert.equal(result.status, 'fail');
    assert.match(result.reason, /^resolve-connect-error: /);
    assert.match(result.reason, /http:\/\/peer-a\.test/);
    assert.match(result.reason, /ECONNREFUSED/);
  }
});

test('タイムアウト（AbortSignal.timeout）は pass にならず fail になり、タイムアウトと分かる理由が残る', async () => {
  for (const name of ['TimeoutError', 'AbortError']) {
    const error = Object.assign(new Error('The operation was aborted due to timeout'), { name });
    const result = await runSinglePair(throwingFetch(error));
    assert.equal(result.status, 'fail', name);
    assert.match(result.reason, /^resolve-timeout: /, name);
    assert.match(result.reason, /制限時間内に応答しなかった/, name);
    // 接続失敗と同じ理由にまとめない（未起動と遅延を Nightly の結果から切り分けるため）。
    assert.doesNotMatch(result.reason, /resolve-connect-error/, name);
  }
});

test('5xx の HTML 応答は fail になる（プロキシのエラーページを解決結果と見なさない）', async () => {
  const result = await runSinglePair(
    recordingFetch(() => textResponse(502, '<html><body>Bad Gateway</body></html>')),
  );
  assert.equal(result.status, 'fail');
  assert.match(result.reason, /^HTTP 502: /);
  assert.match(result.reason, /Bad Gateway/);
});

test('2xx でも JSON オブジェクトでなければ fail になる', async () => {
  for (const body of ['<html>ok</html>', '"did:key:z6Mk"', '[]']) {
    const result = await runSinglePair(recordingFetch(() => textResponse(200, body)));
    assert.equal(result.status, 'fail', body);
    assert.match(result.reason, /JSON (以外|オブジェクト以外)の応答を返した/, body);
  }
});

test('didResolutionMetadata.error があれば fail になり、その値が理由に残る', async () => {
  const result = await runSinglePair(
    recordingFetch(() =>
      jsonResponse(200, { didResolutionMetadata: { error: 'notFound' }, didDocument: null }),
    ),
  );
  assert.equal(result.status, 'fail');
  assert.match(result.reason, /^didResolutionMetadata\.error: notFound$/);
});

test('2xx でも didDocument.id が要求した DID と違えば fail になり、両方の id が理由に載る', async () => {
  const other = 'did:key:z6MkrwgwKPGunsZjHEYJBGYjQH95YTefowBVXfkV753pocgB';
  const result = await runSinglePair(
    recordingFetch(() => jsonResponse(200, resolutionResultFor(other))),
  );
  assert.equal(result.status, 'fail');
  assert.match(result.reason, /^did-mismatch: /);
  assert.ok(result.reason.includes(SINGLE_PAIR_DID), '要求した DID が理由に無い');
  assert.ok(result.reason.includes(other), '解決結果の id が理由に無い');
});

test('検証鍵を取り出せない DID Document（verificationMethod の欠落・空・鍵マテリアル欠落・type 欠落）は fail になる', async () => {
  const vm = didDocumentFor(SINGLE_PAIR_DID).verificationMethod[0];
  const cases = [
    [
      'verificationMethod 自体が無い',
      { verificationMethod: undefined },
      /verification-method-missing/,
    ],
    ['空配列', { verificationMethod: [] }, /verification-method-missing/],
    ['配列ではない', { verificationMethod: vm }, /verification-method-missing/],
    [
      '鍵マテリアル欠落',
      { verificationMethod: [{ id: vm.id, type: vm.type, controller: vm.controller }] },
      /publicKeyJwk \/ publicKeyMultibase \/ publicKeyBase58 のいずれも無い/,
    ],
    [
      'type 欠落',
      { verificationMethod: [{ id: vm.id, publicKeyMultibase: vm.publicKeyMultibase }] },
      /文字列の id \/ type が無い/,
    ],
    [
      '要素がオブジェクトではない',
      { verificationMethod: ['did:key:z6Mk#0'] },
      /オブジェクトではない/,
    ],
  ];
  for (const [label, patch, expected] of cases) {
    const result = await runSinglePair(recordingFetch(() => brokenDocument(patch)));
    assert.equal(result.status, 'fail', label);
    assert.match(result.reason, expected, label);
  }
});

test('DID Document 単体（Resolution Result で包まれない応答）も同じ検査を通れば pass になる', async () => {
  // DIF HTTPS Binding は Accept 次第で両形式を返す。包まれない応答を一律 fail にすると、
  // 実際には解決できているピアを落とし続けることになるため、形式の違いだけでは落とさない。
  const result = await runSinglePair(
    recordingFetch((did) => jsonResponse(200, didDocumentFor(did))),
  );
  assert.equal(result.status, 'pass');
});

/** did:key の DID Document を、指定した表現の検証鍵 1 件だけを持つ形に差し替える。 */
function documentWithKey(keyMaterial, type = 'Ed25519VerificationKey2018') {
  const document = didDocumentFor(SINGLE_PAIR_DID);
  const { id, controller } = document.verificationMethod[0];
  document.verificationMethod = [{ id, type, controller, ...keyMaterial }];
  return document;
}

test('did:key の正しい検証鍵は表現が違っても pass になる（multibase / base58 / JWK）', async () => {
  // 同じ did:key でも鍵マテリアルの表現はピアの解決器で異なり、`key-did-resolver`（veramo /
  // sphereon アダプタが使う）は Ed25519VerificationKey2018 + publicKeyBase58、didkit（ssi）は
  // publicKeyJwk で返す。受理する表現を絞ると、鍵を正しく返しているピアを表現の違いだけで fail に
  // し、本物の非互換を埋もれさせる。期待値（`expectedKey`）は同じ鍵の 3 表現を持つ。
  const cases = [
    ['publicKeyMultibase', { publicKeyMultibase: KEY_FIXTURE.expectedKey.publicKeyMultibase }],
    ['publicKeyBase58', { publicKeyBase58: KEY_FIXTURE.expectedKey.publicKeyBase58 }],
    // ピアは kid / alg を足して返すことがある（期待値の各メンバが一致すればよい）。
    ['publicKeyJwk', { publicKeyJwk: { ...KEY_FIXTURE.expectedKey.publicKeyJwk, alg: 'EdDSA' } }],
  ];
  for (const [label, keyMaterial] of cases) {
    const result = await runSinglePair(
      recordingFetch(() => jsonResponse(200, documentWithKey(keyMaterial))),
    );
    assert.equal(result.status, 'pass', label);
    assert.equal(result.reason, undefined, label);
  }
});

test('did:key で要求した DID の鍵でない検証鍵は fail になる（id だけ合う解決器を通さない）', async () => {
  // did:key は method-specific id 自体が multicodec された公開鍵なので、解決結果が「要求した DID の
  // 鍵」を返したことまで確かめられる。ここが鍵マテリアルの有無だけの検査だと、無関係な鍵を返す
  // 解決器が pass し、実駆動 5 ペアのうち did:key の 3 ペアが素通りする。
  const otherKey = PAIRS.didResolution.fixtures.key.expectedKey;
  const cases = [
    ['でたらめな base58', { publicKeyBase58: '6Mk'.repeat(10) }],
    [
      '別の did:key の multibase',
      { publicKeyMultibase: 'z6MkrwgwKPGunsZjHEYJBGYjQH95YTefowBVXfkV753pocgB' },
    ],
    [
      '1 文字違いの JWK',
      { publicKeyJwk: { ...otherKey.publicKeyJwk, x: `A${otherKey.publicKeyJwk.x.slice(1)}` } },
    ],
    // multicodec を外した生鍵をそのまま multibase 値として返す（表現の取り違え）。
    ['表現の取り違え', { publicKeyMultibase: `z${otherKey.publicKeyBase58}` }],
  ];
  for (const [label, keyMaterial] of cases) {
    const result = await runSinglePair(
      recordingFetch(() => jsonResponse(200, documentWithKey(keyMaterial))),
    );
    assert.equal(result.status, 'fail', label);
    assert.match(result.reason, /^verification-method-mismatch: /, label);
    assert.ok(result.reason.includes(SINGLE_PAIR_DID), label);
  }
});

test('fixture の期待公開鍵と一致する検証鍵が無ければ fail になる（別の鍵を返す解決器を通さない）', async () => {
  // did:jwk も DID 自体が公開鍵を含むため、解決結果が要求した鍵を返したことまで確かめられる。
  const fixture = PAIRS.didResolution.fixtures.jwk;
  const otherKeyDocument = didDocumentFor(fixture.did);
  otherKeyDocument.verificationMethod[0].publicKeyJwk = {
    ...fixture.expectedKey.publicKeyJwk,
    x: 'AAAAAietHL7_qBhKlI9w7acelyrPyPY-HbelS8ATuDA',
  };
  const result = await runSinglePair(
    recordingFetch(() => jsonResponse(200, otherKeyDocument)),
    singleFixtureConfig('jwk', fixture),
  );
  assert.equal(result.status, 'fail');
  assert.match(result.reason, /^verification-method-mismatch: /);
  assert.ok(result.reason.includes(fixture.did));
});

test('期待鍵の JWK が空なら一致と見なさない（任意の鍵を通す fail-open に戻さない）', async () => {
  // 照合は「期待値の各メンバが一致すること」を見るため、`expectedKey.publicKeyJwk` が `{}` に
  // 退行すると条件が空になり、`publicKeyJwk` を持つ**任意の**検証鍵が一致扱いになる。
  // 照合できない期待値は一致と見なさない。
  const fixture = PAIRS.didResolution.fixtures.jwk;
  const result = await runSinglePair(
    recordingFetch((did) => jsonResponse(200, didDocumentFor(did))),
    singleFixtureConfig('jwk', { did: fixture.did, expectedKey: { publicKeyJwk: {} } }),
  );
  assert.equal(result.status, 'fail');
  assert.match(result.reason, /^verification-method-mismatch: /);
});

/**
 * 実駆動する fixture の `expectedKey` が持つべき鍵マテリアル。表現を 1 つ落とすと、
 * その表現で返すピアの照合だけが静かに無効になる。did:key はピアごとに表現が割れる
 * （multibase / base58 / JWK）ので 3 表現すべて、did:jwk の verificationMethod は定義上
 * JWK そのものなので JWK を持つ。
 */
const REQUIRED_KEY_MEMBERS = {
  key: ['publicKeyMultibase', 'publicKeyBase58', 'publicKeyJwk'],
  jwk: ['publicKeyJwk'],
};

/** JWK が鍵を一意に決めるために要るメンバ（EC は `y` が無いと曲線上の点が定まらない）。 */
const requiredJwkMembers = (jwk) =>
  jwk?.kty === 'EC' ? ['kty', 'crv', 'x', 'y'] : ['kty', 'crv', 'x'];

/** `members` のうち `object` で空（未設定・空文字）のものを返す。 */
const missingMembers = (object, members) => members.filter((member) => !object?.[member]);

test('実駆動する fixture（did:key / did:jwk）は照合に足りる期待鍵を持つ', () => {
  // `expectedKey` のメンバが欠けると鍵の照合が（表現ごとに、JWK が空なら丸ごと）無効になり、
  // 無関係な鍵を返す解決器が静かに pass する。欠落を設定側で固定する。
  for (const [method, members] of Object.entries(REQUIRED_KEY_MEMBERS)) {
    const { expectedKey } = PAIRS.didResolution.fixtures[method];
    assert.ok(expectedKey, `${method} の fixture に expectedKey が無い`);
    assert.deepEqual(
      missingMembers(expectedKey, members),
      [],
      `${method} の expectedKey に無い鍵の表現がある`,
    );
    const jwk = expectedKey.publicKeyJwk;
    assert.deepEqual(
      missingMembers(jwk, requiredJwkMembers(jwk)),
      [],
      `${method} の expectedKey.publicKeyJwk に鍵を一意に決めるメンバが無い`,
    );
  }
});
