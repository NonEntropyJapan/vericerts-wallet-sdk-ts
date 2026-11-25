// test/interop/test-support/run-peer-matrix.fixtures.mjs
//
// `run-peer-matrix.*.test.mjs` 共通の fetch / spawn スタブと BASE_CONFIG（外部 I/O はすべてモック）。

import { run } from '../run-peer-matrix.mjs';

/** `fetchJson` が読む最小限の Response 互換オブジェクト。 */
export function jsonResponse(status, body) {
  return { ok: status >= 200 && status < 300, status, text: async () => JSON.stringify(body) };
}

/**
 * `${method} ${url}` をキーに応答を引く fetch スタブ。未登録の呼び出しは例外にする
 * （テストが意図せず実ネットワークへ依存していないことを保証する）。
 */
export function routedFetch(routes) {
  return async (url, options) => {
    const key = `${options?.method ?? 'GET'} ${url}`;
    const handler = routes[key];
    if (!handler) {
      throw new Error(`unmocked fetch call: ${key}`);
    }
    return handler(options);
  };
}

/** `spawnSync` 互換のスタブ。固定の戻り値を返す。 */
export const spawnStub = (result) => () => result;

/**
 * uniform アダプタ（`adapters/{vericerts,veramo}/server.mjs`）の入口検査をそのまま写したスタブ。
 * コンパクト JWT-VC 文字列以外（native ピアの LD-Proof オブジェクト）は HTTP 400 で拒否する。
 * この拒否理由が `pairs.json` の `knownIncompatible` の `reasonIncludes` と一致する。
 */
export const ADAPTER_ENTRY_CHECK_ERROR = 'jwt is required (string)';
export const uniformVerify = (handler) => (options) =>
  typeof JSON.parse(options.body).jwt === 'string'
    ? handler(options)
    : jsonResponse(400, { verified: false, error: ADAPTER_ENTRY_CHECK_ERROR });

/**
 * 実設定（`pairs.json`）と同じ構造の非互換登録。native 発行 × uniform 検証は `skipped` ではなく
 * 実際に試行し、登録どおりの理由の fail だけが `known-incompatible` に畳まれる。
 */
export const NATIVE_FORMAT_INCOMPATIBLE = ['peerA', 'peerB'].map((verifier) => ({
  pair: `interop:nativeA:${verifier}`,
  issue: 1,
  reasonIncludes: ADAPTER_ENTRY_CHECK_ERROR,
  note: 'native ピアの LD-Proof を uniform アダプタの入口検査が拒否する',
}));

export const BASE_CONFIG = {
  knownIncompatible: NATIVE_FORMAT_INCOMPATIBLE,
  uniformPeers: [
    { name: 'peerA', baseUrl: 'http://peer-a.test', kind: 'uniform' },
    { name: 'peerB', baseUrl: 'http://peer-b.test', kind: 'uniform' },
  ],
  nativePeers: [
    {
      name: 'nativeA',
      baseUrl: 'http://native-a.test',
      kind: 'native-vc-api',
      issuerDid: 'did:example:native-a',
    },
  ],
  waltidProtocolPeers: {
    issuer: { name: 'waltid-issuer', baseUrl: 'http://waltid-issuer.test' },
    verifier: { name: 'waltid-verifier', baseUrl: 'http://waltid-verifier.test' },
  },
  externalPrerequisitePeers: [
    {
      name: 'ext',
      baseUrl: 'http://ext.test',
      requiresEnv: 'EXT_SANDBOX_BASE_URL',
      note: 'test prerequisite',
    },
  ],
};

/** 全ステップが成功する happy-path 用のルート一式。 */
export function happyRoutes() {
  return {
    'POST http://peer-a.test/vc/issue': () => jsonResponse(200, { jwt: 'jwt-from-a' }),
    'POST http://peer-b.test/vc/issue': () => jsonResponse(200, { jwt: 'jwt-from-b' }),
    'POST http://peer-a.test/vc/verify': uniformVerify(() => jsonResponse(200, { verified: true })),
    'POST http://peer-b.test/vc/verify': uniformVerify(() => jsonResponse(200, { verified: true })),
    'POST http://native-a.test/credentials/verify': () =>
      jsonResponse(200, { checks: ['proof'], warnings: [], errors: [] }),
    'POST http://native-a.test/credentials/issue': () =>
      jsonResponse(201, { verifiableCredential: { proof: {} } }),
    'GET http://ext.test/': () => jsonResponse(200, {}),
  };
}

const happySpawn = () =>
  spawnStub({
    error: undefined,
    stdout: JSON.stringify({
      results: [
        { pair: 'interop:waltid-issuer:vericerts', status: 'pass' },
        { pair: 'interop:vericerts:waltid-verifier', status: 'pass' },
      ],
    }),
    stderr: '',
  });

export const runWith = (overrides) =>
  run({
    config: BASE_CONFIG,
    fetchImpl: routedFetch(happyRoutes()),
    spawnImpl: happySpawn(),
    env: { EXT_SANDBOX_BASE_URL: 'http://ext.test' },
    ...overrides,
  });

/** 生テキスト応答（HTML 等、JSON でない本文）を返す Response 互換オブジェクト。 */
export function textResponse(status, text) {
  return { ok: status >= 200 && status < 300, status, text: async () => text };
}
