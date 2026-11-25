// test/interop/__tests__/did-resolution/fixtures.mjs
//
// `did-resolution/*.test.mjs` 共通の fetch スタブと設定（外部 I/O はすべてモック）。
// 実ピアを起動せずに run-did-resolution-matrix.mjs の判定ロジックを駆動する。

import { readFileSync } from 'node:fs';
import { run } from '../../run-did-resolution-matrix.mjs';

/** `pairs.json`（実設定）。マトリクスの件数・fixture の DID を参照するテストが読む。 */
export const PAIRS = JSON.parse(readFileSync(new URL('../../pairs.json', import.meta.url), 'utf8'));

/**
 * compose のサービス名 → テストで使うホスト実ポート。`pairs.json` のピアは `service` /
 * `containerPort` を持ち、ランナーが `docker compose port` で実ポートを引く。
 */
const HOST_PORTS = { sphereon: 49096, veramo: 49091, didkit: 49092, 'ebsi-proxy': 49095 };

/**
 * `docker compose port` の `spawnSync` 互換スタブ。実設定（`pairs.json`）で駆動するテストが
 * 実 Docker へ出ていかないようにする。未知のサービスは失敗させる（黙って既定へ戻さない）。
 */
export function composePortStub(ports = HOST_PORTS) {
  return (_command, args) => {
    const port = ports[args[4]];
    if (port === undefined) {
      return { error: undefined, status: 1, stdout: '', stderr: `no such service: ${args[4]}` };
    }
    return { error: undefined, status: 0, stdout: `127.0.0.1:${port}\n`, stderr: '' };
  };
}

/** `resolveDidWithPeer` が読む最小限の Response 互換オブジェクト（JSON 本文）。 */
export function jsonResponse(status, body) {
  return { ok: status >= 200 && status < 300, status, text: async () => JSON.stringify(body) };
}

/** 生テキスト応答（HTML 等、JSON でない本文）を返す Response 互換オブジェクト。 */
export function textResponse(status, text) {
  return { ok: status >= 200 && status < 300, status, text: async () => text };
}

/** 解決要求の URL から DID を取り出す（`<resolvePath>` の末尾が encodeURIComponent された DID）。 */
export function didFromUrl(url) {
  return decodeURIComponent(String(url).split('/').pop());
}

/**
 * DID に埋まった公開鍵を、その DID を正しく解決したピアが返す表現に直す。
 * did:jwk は method-specific id（base64url された JWK）、did:key は method-specific id が
 * そのまま `publicKeyMultibase`。他メソッドは DID から鍵を導けないので固定値を置く。
 */
function publicKeyOf(did) {
  const [, method, id] = did.split(':');
  if (method === 'jwk') {
    return { publicKeyJwk: JSON.parse(Buffer.from(id, 'base64url').toString('utf8')) };
  }
  if (method === 'key') return { publicKeyMultibase: id };
  return { publicKeyMultibase: 'z6MkjokRbxaU4C5YkUxGnLXvY2t85taRpBmLwRt6CakReKeh' };
}

/** 検証鍵を 1 件持つ正常な DID Document（要求された DID から導かれる鍵をそのまま返す）。 */
export function didDocumentFor(did) {
  const publicKey = publicKeyOf(did);
  const verificationMethod = {
    id: `${did}#0`,
    type: publicKey.publicKeyJwk ? 'JsonWebKey2020' : 'Ed25519VerificationKey2020',
    controller: did,
    ...publicKey,
  };
  return {
    '@context': 'https://www.w3.org/ns/did/v1',
    id: did,
    verificationMethod: [verificationMethod],
    authentication: [verificationMethod.id],
  };
}

/** DIF DID Resolution Result 形式（`didDocument` を内包する）の正常応答。 */
export function resolutionResultFor(did) {
  return {
    didResolutionMetadata: { contentType: 'application/did+ld+json' },
    didDocument: didDocumentFor(did),
    didDocumentMetadata: {},
  };
}

/**
 * DID ごとに応答を決める fetch スタブ。既定はすべて正常解決。
 * 要求された DID を `requested` に記録するので、「どの DID を実際に叩いたか」を検査できる
 * （did:ethr の全版解決や、skipped のペアが通信していないことの確認に使う）。
 */
export function recordingFetch(handler = (did) => jsonResponse(200, resolutionResultFor(did))) {
  const requested = [];
  const impl = async (url) => {
    const did = didFromUrl(url);
    requested.push(did);
    return handler(did, url);
  };
  impl.requested = requested;
  return impl;
}

/**
 * fail-closed 検査用の最小設定（1 メソッド × 1 ピア）。実設定の did:key fixture をそのまま使い、
 * 期待鍵（`expectedKey`）の突き合わせも含めて `pairs.json` と同じ条件で駆動する。
 */
export const KEY_FIXTURE = PAIRS.didResolution.fixtures.key;
export const SINGLE_PAIR_DID = KEY_FIXTURE.did;

/** 1 メソッド × 1 ピアだけの設定。fixture を差し替えて判定ロジックを個別に駆動する。 */
export function singleFixtureConfig(method, fixture) {
  return {
    didResolution: {
      matrix: { [method]: ['peerA'] },
      peers: { peerA: { baseUrl: 'http://peer-a.test', resolvePath: '/identifiers/' } },
      fixtures: { [method]: fixture },
    },
  };
}

export const SINGLE_PAIR_CONFIG = singleFixtureConfig('key', KEY_FIXTURE);

/** did:ethr の複数 EIP-1056 版を駆動する設定（版の配列をそのまま fixture にする）。 */
export function ethrConfig(eip1056Versions) {
  return singleFixtureConfig('ethr', { eip1056Versions });
}

/** 設定を 1 回実行し、唯一の PairResult を返す。 */
export async function runSinglePair(fetchImpl, config = SINGLE_PAIR_CONFIG) {
  const { results } = await run({ config, fetchImpl, spawnImpl: composePortStub(), env: {} });
  if (results.length !== 1) {
    throw new Error(`最小設定の結果が 1 件ではない: ${JSON.stringify(results)}`);
  }
  return results[0];
}
