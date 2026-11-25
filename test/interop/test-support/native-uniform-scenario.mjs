// test/interop/test-support/native-uniform-scenario.mjs
//
// `__tests__/run-peer-matrix.native-format.test.mjs` の構成（native 発行 × uniform 検証の 4 ペアだけを動かすための
// 実設定ベースの CONFIG・ルート表・実行ヘルパ）。テスト本体と分けたのは、linterly のディレクトリ行数の上限に
// 収めるためで、中身（検証内容）はテスト側に残している。`*.test.mjs` ではないので単独では実行されない。

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { run } from '../run-peer-matrix.mjs';
import { jsonResponse, routedFetch, spawnStub } from './run-peer-matrix.fixtures.mjs';

export const PAIRS = JSON.parse(readFileSync(new URL('../pairs.json', import.meta.url), 'utf8'));

/** 実設定どおりの 4 ペア（native 発行 × uniform 検証）。 */
export const NATIVE_UNIFORM_PAIRS = PAIRS.nativePeers
  .flatMap((native) =>
    PAIRS.uniformPeers.map((uniform) => `interop:${native.name}:${uniform.name}`),
  )
  .sort();

/** 観測した拒否理由（2026-11-09、実ピア。アダプタの入口検査が返す文言）。 */
export const ENTRY_CHECK_ERROR = 'jwt is required (string)';

const baseUrlOfName = (name) => `http://${name}.test`;
/** `docker compose port` を介さずスタブへ直接届かせる（`service` / `containerPort` を外す）。 */
const withFixedBaseUrl = ({ service: _s, containerPort: _c, ...peer }) => ({
  ...peer,
  baseUrl: baseUrlOfName(peer.name),
});

/**
 * 実設定のピア名・`issuerDid`・`knownIncompatible` をそのまま使い、ホストポート解決だけを挟まない
 * 構成。外部前提ピア（EBSI）と walt.id のプロトコル層はこのテストの対象外。
 */
const CONFIG = {
  uniformPeers: PAIRS.uniformPeers.map(withFixedBaseUrl),
  nativePeers: PAIRS.nativePeers.map(withFixedBaseUrl),
  waltidProtocolPeers: {
    issuer: { name: 'waltid-issuer', baseUrl: 'http://waltid-issuer.test' },
    verifier: { name: 'waltid-verifier', baseUrl: 'http://waltid-verifier.test' },
  },
  externalPrerequisitePeers: [],
  knownIncompatible: PAIRS.knownIncompatible,
};

const waltidSpawn = spawnStub({
  error: undefined,
  stdout: JSON.stringify({
    results: [
      { pair: 'interop:waltid-issuer:vericerts', status: 'pass' },
      { pair: 'interop:vericerts:waltid-verifier', status: 'pass' },
    ],
  }),
  stderr: '',
});

/**
 * 4 ペアだけを動かすためのルート。`uniformVerify` は native 発行 VC（LD-Proof オブジェクト）が
 * 届いたときの uniform ピアの応答で、シナリオごとに差し替える。
 * uniform 発行の JWT（文字列）はつねに受理して、uniform×uniform の結果を汚さない。
 */
function routes({ uniformVerify, nativeIssue }) {
  const table = {};
  for (const peer of PAIRS.uniformPeers) {
    const base = baseUrlOfName(peer.name);
    table[`POST ${base}/vc/issue`] = () => jsonResponse(200, { jwt: `jwt-from-${peer.name}` });
    table[`POST ${base}/vc/verify`] = (options) =>
      typeof JSON.parse(options.body).jwt === 'string'
        ? jsonResponse(200, { verified: true })
        : uniformVerify(options);
  }
  for (const peer of PAIRS.nativePeers) {
    const base = baseUrlOfName(peer.name);
    table[`POST ${base}/credentials/issue`] =
      nativeIssue ?? (() => jsonResponse(201, { verifiableCredential: { proof: {} } }));
    table[`POST ${base}/credentials/verify`] = () =>
      jsonResponse(200, { checks: ['proof'], warnings: [], errors: [] });
  }
  return table;
}

/** 4 ペアの `{ status, reason }` をペア名順で返す。 */
export async function statusesOfNativeUniformPairs(
  overrides,
  knownIncompatible = CONFIG.knownIncompatible,
) {
  const { results } = await run({
    config: { ...CONFIG, knownIncompatible },
    fetchImpl: routedFetch(routes(overrides)),
    spawnImpl: waltidSpawn,
    env: {},
  });
  return NATIVE_UNIFORM_PAIRS.map((pair) => {
    const result = results.find((r) => r.pair === pair);
    assert.ok(result, `${pair} が結果に無い（マトリクスから黙って落ちている）`);
    return result;
  });
}
