// test/interop/__tests__/did-resolution/peer-accept.test.mjs
//
// DID 解決要求の Accept ヘッダをピア単位で上書きできることの回帰テスト。
//
// 背景: pinned の `didkit-http` は DIF DID Resolution HTTPS Binding の Resolution Result を
// 規定の形で返さない。`Accept: application/ld+json;profile="https://w3id.org/did-resolution"` に
// 対して `{"Success":{"content":"<DID Document を JSON 文字列にしたもの>", …}}` という Rust 側の
// enum 表現をそのまま返すため、`didDocument` も `id` も直下に無く、ランナーは
// `did-mismatch: … 解決結果の id (undefined) …` で fail していた（Nightly の実観測）。
// 一方 `Accept: application/did+ld+json` では DID Document 表現を正しく返す。
//
// ここで固定するのは次の 3 点:
//   1. `resolveAccept` を持つピアにはその値を送る（didkit が解決できるようになる）
//   2. `resolveAccept` を持たないピアには既定の Resolution Result profile を送り続ける
//      （規定どおり返せるピアへの要求を緩めない。`didResolutionMetadata.error` の検査を残す）
//   3. `Success` ラッパーを 2xx で返されても pass にしない（didkit が同じ形へ戻ったら fail で気づく）
//
// 実行方法: リポジトリルートから
//   node --test test/interop/__tests__/did-resolution/peer-accept.test.mjs

import assert from 'node:assert/strict';
import test from 'node:test';
import { run } from '../../run-did-resolution-matrix.mjs';
import {
  composePortStub,
  didDocumentFor,
  didFromUrl,
  jsonResponse,
  KEY_FIXTURE,
  PAIRS,
  runSinglePair,
  SINGLE_PAIR_DID,
  textResponse,
} from './fixtures.mjs';

/** DIF Binding で Resolution Result を要求する既定の Accept（`lib/did-resolution-clients.mjs`）。 */
const DEFAULT_ACCEPT = 'application/ld+json;profile="https://w3id.org/did-resolution"';

/** `pairs.json` の didkit ピアが使う Accept。 */
const DIDKIT_ACCEPT = 'application/did+ld+json';

/** 送られた Accept ヘッダを記録する fetch スタブ（既定はすべて正常な DID Document を返す）。 */
function headerRecordingFetch(handler = (did) => jsonResponse(200, didDocumentFor(did))) {
  const accepts = [];
  const impl = async (url, init) => {
    accepts.push(init?.headers?.accept);
    return handler(didFromUrl(url), init);
  };
  impl.accepts = accepts;
  return impl;
}

/**
 * pinned の `didkit-http` の応答を再現する fetch スタブ（2026-11-13 にローカルの compose で実観測）。
 *
 * Accept の内容交渉は実装されておらず、ヘッダ全体を 1 個のメディア型トークンとして完全一致で見る。
 * そのため複数値や `q=` を足した Accept は 406 になり、「両方を受理する Accept」は書けない。
 */
function didkitHttpStub(did) {
  return async (_url, init) => {
    const accept = init?.headers?.accept;
    if (accept === DIDKIT_ACCEPT) {
      return jsonResponse(200, didDocumentFor(did));
    }
    if (accept === DEFAULT_ACCEPT) {
      // Rust 側の externally tagged enum がそのまま出た形。`content` は DID Document の JSON 文字列。
      return jsonResponse(200, {
        Success: {
          content: JSON.stringify(didDocumentFor(did)),
          metadata: { contentType: 'application/did+ld+json' },
          document_metadata: { deactivated: null },
        },
      });
    }
    return textResponse(406, `unknown DID document representation \`${accept}\``);
  };
}

/** `pairs.json` の実設定から did:key × didkit の 1 ペアだけを取り出した設定。 */
function didkitKeyConfig() {
  return {
    didResolution: {
      matrix: { key: ['didkit'] },
      peers: { didkit: PAIRS.didResolution.peers.didkit },
      fixtures: { key: PAIRS.didResolution.fixtures.key },
    },
  };
}

/** 設定を 1 回実行し、唯一の PairResult を返す。 */
async function runDidkitPair(fetchImpl) {
  const { results } = await run({
    config: didkitKeyConfig(),
    fetchImpl,
    spawnImpl: composePortStub(),
    env: {},
  });
  assert.equal(results.length, 1, `結果が 1 件ではない: ${JSON.stringify(results)}`);
  return results[0];
}

test('didkit は did:key を解決できる（Resolution Result profile では Success ラッパーを返すピア）', async () => {
  // 修正前はこのペアに既定の Accept を送っていたため Success ラッパーが返り、
  // `did-mismatch: … 解決結果の id (undefined) …` で fail していた。
  const fetchImpl = headerRecordingFetch(didkitHttpStub(KEY_FIXTURE.did));
  const result = await runDidkitPair(fetchImpl);
  assert.equal(result.status, 'pass', result.reason);
  assert.deepEqual(fetchImpl.accepts, [DIDKIT_ACCEPT]);
});

test('pairs.json の didkit ピアは Accept を DID Document 表現に上書きしている', () => {
  // 設定が落ちると同じ Nightly 失敗へ静かに戻る（ランナー側のコードは変わらないため気づけない）。
  assert.equal(PAIRS.didResolution.peers.didkit.resolveAccept, DIDKIT_ACCEPT);
});

test('resolveAccept を持たないピアには既定の Resolution Result profile を送り続ける', async () => {
  // 既定を緩めて全ピアを DID Document 表現に倒すと、`didResolutionMetadata.error` を見る検査が
  // どのピアに対しても働かなくなる。上書きはピア単位に閉じる。
  const fetchImpl = headerRecordingFetch();
  const result = await runSinglePair(fetchImpl);
  assert.equal(result.status, 'pass', result.reason);
  assert.deepEqual(fetchImpl.accepts, [DEFAULT_ACCEPT]);
});

test('Success ラッパーを 2xx で返されても pass にしない（didkit が同じ形へ戻れば fail で気づく）', async () => {
  // `resolveAccept` が効かなくなった場合や、didkit が DID Document 表現でも同じ包み方を
  // するようになった場合に、「解決できた」と誤認しないことを固定する。
  const result = await runSinglePair(
    headerRecordingFetch(async (did) => {
      const inner = didDocumentFor(did);
      return jsonResponse(200, {
        Success: { content: JSON.stringify(inner), metadata: {}, document_metadata: {} },
      });
    }),
  );
  assert.equal(result.status, 'fail');
  assert.match(result.reason, /^did-mismatch: /);
  assert.ok(result.reason.includes(SINGLE_PAIR_DID), '要求した DID が理由に無い');
});

test('ピアが Accept を受理しなければ（406）pass にならず fail になる', async () => {
  // didkit の内容交渉は完全一致なので、上書き値が実装側とずれると 406 になる。
  // 406 を「解決できた」と見なさないことと、理由から Accept のずれに辿れることを固定する。
  const result = await runDidkitPair(
    headerRecordingFetch(async (_did, init) =>
      textResponse(406, `unknown DID document representation \`${init?.headers?.accept}\``),
    ),
  );
  assert.equal(result.status, 'fail');
  assert.match(result.reason, /^HTTP 406: /);
  assert.match(result.reason, /unknown DID document representation/);
});
