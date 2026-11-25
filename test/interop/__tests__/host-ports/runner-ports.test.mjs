// test/interop/__tests__/host-ports/runner-ports.test.mjs
//
// ホストポートの run 単位割り当ての回帰テスト。実ピア・実 Docker 無しで、
// `spawnImpl` が返す `docker compose port` の出力だけを与えて配線を駆動する。
//
// 固定しているのは次の 3 点:
//   - `uniformPeers` / `nativePeers` / `externalPrerequisitePeers` の宛先が、`docker compose port` が
//     返した実ポートになる（`routedFetch` は未登録の宛先を例外にするので、別ポートへ飛べば落ちる）
//   - 実ポートを引けなかったピアは `pairs.json` の既定ポートへ**戻さず**、そのペアを fail にする
//   - `waltidProtocolPeers` の `baseUrl`（compose ネットワーク内のアドレス）は書き換えない
//
// 実行方法: node --test test/interop/__tests__/host-ports/runner-ports.test.mjs

import assert from 'node:assert/strict';
import { once } from 'node:events';
import { readFileSync } from 'node:fs';
import { createServer } from 'node:http';
import test from 'node:test';
import { checkPeerAlive } from '../../lib/peer-clients.mjs';
import { run as runDidResolution } from '../../run-did-resolution-matrix.mjs';
import { run as runPeerMatrix } from '../../run-peer-matrix.mjs';
import { jsonResponse, routedFetch } from '../../test-support/run-peer-matrix.fixtures.mjs';
import { resolutionResultFor } from '../did-resolution/fixtures.mjs';

/** compose のサービス名 → Docker が割り当てたホストポート。 */
const HOST_PORTS = { 'svc-a': 49190, 'svc-n': 49191, 'svc-e': 49192, 'ebsi-proxy': 49193 };

/**
 * `spawnSync` 互換スタブ。`docker compose port <service> <port>` には割り当て済みの実ポートを、
 * walt.id ドライバの呼び出しには両ペア pass の JSON を返す。
 * `failures[service]` を渡したサービスだけ `docker compose port` を失敗させる。
 */
function spawnStub({ failures = {} } = {}) {
  const calls = [];
  const impl = (command, args) => {
    calls.push({ command, args });
    if (args[3] !== 'port') {
      return {
        error: undefined,
        status: 0,
        stdout: JSON.stringify({
          results: [
            { pair: 'interop:waltid-issuer:vericerts', status: 'pass' },
            { pair: 'interop:vericerts:waltid-verifier', status: 'pass' },
          ],
        }),
        stderr: '',
      };
    }
    const service = args[4];
    if (failures[service]) {
      return { error: undefined, status: 1, stdout: '', stderr: failures[service] };
    }
    return {
      error: undefined,
      status: 0,
      stdout: `127.0.0.1:${HOST_PORTS[service]}\n`,
      stderr: '',
    };
  };
  impl.calls = calls;
  return impl;
}

const PEER_CONFIG = {
  uniformPeers: [{ name: 'peerA', service: 'svc-a', containerPort: 8090, kind: 'uniform' }],
  nativePeers: [
    {
      name: 'nativeA',
      service: 'svc-n',
      containerPort: 3000,
      kind: 'native-vc-api',
      issuerDid: 'did:example:native-a',
    },
  ],
  waltidProtocolPeers: {
    issuer: { name: 'waltid-issuer', baseUrl: 'http://waltid-issuer:7002' },
    verifier: { name: 'waltid-verifier', baseUrl: 'http://waltid-verifier:7003' },
  },
  externalPrerequisitePeers: [
    {
      name: 'ext',
      service: 'svc-e',
      containerPort: 8095,
      requiresEnv: 'EXT_SANDBOX_BASE_URL',
      note: 'test prerequisite',
    },
  ],
};

/** 実ポート（49190 等）宛てだけを受け付けるルート。既定ポートへ飛べば未登録で例外になる。 */
const resolvedRoutes = () => ({
  'POST http://localhost:49190/vc/issue': () => jsonResponse(200, { jwt: 'jwt-from-a' }),
  'POST http://localhost:49190/vc/verify': () => jsonResponse(200, { verified: true }),
  'POST http://localhost:49191/credentials/issue': () =>
    jsonResponse(201, { verifiableCredential: { proof: {} } }),
  'POST http://localhost:49191/credentials/verify': () =>
    jsonResponse(200, { checks: ['proof'], warnings: [], errors: [] }),
  'GET http://localhost:49192/': () => jsonResponse(200, {}),
});

const statusOf = (results, pair) => results.find((r) => r.pair === pair);

test('VC マトリクスのピアは docker compose port が返した実ポートを宛先にする', async () => {
  const spawnImpl = spawnStub();
  const { results } = await runPeerMatrix({
    config: PEER_CONFIG,
    fetchImpl: routedFetch(resolvedRoutes()),
    spawnImpl,
    env: { EXT_SANDBOX_BASE_URL: 'http://ext.test' },
  });
  assert.equal(statusOf(results, 'interop:peerA:peerA').status, 'pass');
  assert.equal(statusOf(results, 'interop:peerA:nativeA').status, 'pass');
  assert.equal(statusOf(results, 'interop:nativeA:nativeA').status, 'pass');
  assert.equal(statusOf(results, 'interop:ext:smoke').status, 'pass');
  // ピアごとにちょうど 1 回ずつ `docker compose port` を引く。
  assert.deepEqual(
    spawnImpl.calls.filter((c) => c.args[3] === 'port').map((c) => c.args.slice(4)),
    [
      ['svc-a', '8090'],
      ['svc-n', '3000'],
      ['svc-e', '8095'],
    ],
  );
});

test('EBSI の疎通確認は実ポートの DID Registry の応答で判定する', async (t) => {
  const { externalPrerequisitePeers } = JSON.parse(
    readFileSync(new URL('../../pairs.json', import.meta.url), 'utf8'),
  );
  const config = { ...PEER_CONFIG, externalPrerequisitePeers };
  const registryPath = '/did-registry/v5/identifiers';

  for (const [rootStatus, registryStatus, expected] of [
    [404, 200, 'pass'],
    [200, 503, 'fail'],
  ]) {
    const { results } = await runPeerMatrix({
      config,
      fetchImpl: routedFetch({
        ...resolvedRoutes(),
        'GET http://localhost:49193/': () => jsonResponse(rootStatus, {}),
        [`GET http://localhost:49193${registryPath}`]: () =>
          jsonResponse(registryStatus, { items: [] }),
      }),
      spawnImpl: spawnStub(),
      env: { EBSI_SANDBOX_BASE_URL: 'https://ebsi.test' },
    });
    assert.equal(statusOf(results, 'interop:ebsi:smoke')?.status, expected);
  }

  const requested = [];
  const server = createServer((req, res) => {
    requested.push(req.url);
    if (req.url === registryPath) {
      res.writeHead(302, { location: '/' });
    } else {
      res.writeHead(req.url === '/' ? 200 : 404);
    }
    res.end();
  }).listen(0, '127.0.0.1');
  t.after(() => new Promise((resolve) => server.close(resolve)));
  await once(server, 'listening');
  const baseUrl = `http://127.0.0.1:${server.address().port}`;
  assert.equal(await checkPeerAlive(fetch, baseUrl, registryPath), false);
  assert.deepEqual(requested, [registryPath]);
});

test('walt.id プロトコル層の baseUrl は compose 内部アドレスのまま書き換えない', async () => {
  const spawnImpl = spawnStub();
  await runPeerMatrix({
    config: PEER_CONFIG,
    fetchImpl: routedFetch(resolvedRoutes()),
    spawnImpl,
    env: { EXT_SANDBOX_BASE_URL: 'http://ext.test' },
  });
  const driver = spawnImpl.calls.find((c) => c.args[3] !== 'port');
  assert.ok(driver.args.includes('WALTID_ISSUER_ADMIN_BASE_URL=http://waltid-issuer:7002'));
  assert.ok(driver.args.includes('WALTID_VERIFIER_ADMIN_BASE_URL=http://waltid-verifier:7003'));
});

test('実ポートを引けないピアは既定ポートへ戻さず、そのペアを fail にする', async () => {
  const spawnImpl = spawnStub({ failures: { 'svc-a': 'no such service: svc-a' } });
  const { results } = await runPeerMatrix({
    config: PEER_CONFIG,
    fetchImpl: routedFetch(resolvedRoutes()),
    spawnImpl,
    env: { EXT_SANDBOX_BASE_URL: 'http://ext.test' },
  });
  const selfPair = statusOf(results, 'interop:peerA:peerA');
  assert.equal(selfPair.status, 'fail');
  assert.match(selfPair.reason, /host-port-unresolved/);
  assert.doesNotMatch(selfPair.reason, /localhost:8090/);
  // 解決できたピア同士のペアは影響を受けない。
  assert.equal(statusOf(results, 'interop:nativeA:nativeA').status, 'pass');
});

test('外部前提ピアの実ポートを引けないときは smoke を fail にする', async () => {
  const spawnImpl = spawnStub({ failures: { 'svc-e': 'no such service: svc-e' } });
  const { results } = await runPeerMatrix({
    config: PEER_CONFIG,
    fetchImpl: routedFetch(resolvedRoutes()),
    spawnImpl,
    env: { EXT_SANDBOX_BASE_URL: 'http://ext.test' },
  });
  const smoke = statusOf(results, 'interop:ext:smoke');
  assert.equal(smoke.status, 'fail');
  assert.match(smoke.reason, /host-port-unresolved/);
});

const DID_CONFIG = {
  didResolution: {
    matrix: { key: ['peerA'] },
    peers: { peerA: { service: 'svc-a', containerPort: 8090, resolvePath: '/identifiers/' } },
    fixtures: { key: { did: 'did:key:z6MkjokRbxaU4C5YkUxGnLXvY2t85taRpBmLwRt6CakReKeh' } },
  },
};

test('DID 解決マトリクスのピアも実ポートを宛先にする', async () => {
  const requested = [];
  const fetchImpl = async (url) => {
    requested.push(String(url));
    return jsonResponse(200, resolutionResultFor(DID_CONFIG.didResolution.fixtures.key.did));
  };
  const { results } = await runDidResolution({
    config: DID_CONFIG,
    fetchImpl,
    spawnImpl: spawnStub(),
    env: {},
  });
  assert.equal(results[0].status, 'pass');
  assert.ok(requested.every((url) => url.startsWith('http://localhost:49190/identifiers/')));
});

test('DID 解決で実ポートを引けないピアは skipped ではなく fail にする', async () => {
  const fetchImpl = async () => {
    throw new Error('解決できていないピアへ HTTP を投げてはいけない');
  };
  const { results } = await runDidResolution({
    config: DID_CONFIG,
    fetchImpl,
    spawnImpl: spawnStub({ failures: { 'svc-a': 'no such service: svc-a' } }),
    env: {},
  });
  assert.equal(results[0].status, 'fail');
  assert.match(results[0].reason, /host-port-unresolved/);
});
