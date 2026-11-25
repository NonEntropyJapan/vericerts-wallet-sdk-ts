// test/interop/__tests__/host-ports/compose-ports.test.mjs
//
// `docker-compose.yml` の静的検査。ホスト側のポートは Docker が run ごとに選ぶため
// 固定値を書かない。固定値が戻ると、Release Gate の interop job と Nightly が同じ self-hosted
// ランナーで重なったときに後発が bind に失敗し、ピアの不調ではなく順番待ちでリリースが止まる。
//
// 併せて、コンテナ内ポート（walt.id の `baseUrl` と公開ホスト検査が依存する）が変わっていないこと、
// `pairs.json` の `service` / `containerPort` が compose の実際の公開と一致することを固定する。
// 不一致のままだと `docker compose port` が引けず、全ペアが host-port-unresolved で fail する。
//
// 実行方法: node --test test/interop/__tests__/host-ports/compose-ports.test.mjs

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

const COMPOSE = readFileSync(new URL('../../docker-compose.yml', import.meta.url), 'utf8');
const PAIRS = JSON.parse(readFileSync(new URL('../../pairs.json', import.meta.url), 'utf8'));

/**
 * compose のサービス名 → `ports:` のマッピング一覧。コメント行は除き、1 行フロー形式
 * （`ports: ['127.0.0.1::8090']`）と複数行のブロック形式の両方を拾う。
 */
export function portsByService(text) {
  const services = {};
  let service;
  let collecting = false;
  for (const raw of text.split('\n')) {
    if (raw.trim().startsWith('#')) continue;
    const head = /^ {2}([\w-]+):\s*$/.exec(raw);
    if (head) {
      service = head[1];
      services[service] = services[service] ?? [];
      collecting = false;
      continue;
    }
    if (service === undefined) continue;
    const inline = /^ {4}ports:\s*(.*)$/.exec(raw);
    if (inline) {
      collecting = inline[1] === '';
      for (const m of inline[1].matchAll(/['"]([^'"]+)['"]/g)) services[service].push(m[1]);
      continue;
    }
    const item = /^ {6}-\s*['"]?([^'"\s]+)['"]?\s*$/.exec(raw);
    if (collecting && item) {
      services[service].push(item[1]);
      continue;
    }
    if (/^ {4}\S/.test(raw)) collecting = false;
  }
  return services;
}

const PORTS_BY_SERVICE = portsByService(COMPOSE);
const ALL_MAPPINGS = Object.values(PORTS_BY_SERVICE).flat();

test('compose は ports にホスト側の固定ポートを書かない（Docker が run ごとに割り当てる）', () => {
  assert.ok(ALL_MAPPINGS.length > 0, 'ports エントリを 1 件も抽出できない');
  // `127.0.0.1::<コンテナポート>` = ループバック拘束を保ったままホスト側は Docker に任せる形。
  assert.deepEqual(
    ALL_MAPPINGS.filter((mapping) => !/^127\.0\.0\.1::\d+$/.test(mapping)),
    [],
  );
});

test('compose のコンテナ内ポートは変えない（walt.id の baseUrl と公開ホスト検査が依存する）', () => {
  assert.deepEqual(PORTS_BY_SERVICE.vericerts, ['127.0.0.1::8090']);
  assert.deepEqual(PORTS_BY_SERVICE.veramo, ['127.0.0.1::8091']);
  assert.deepEqual(PORTS_BY_SERVICE.didkit, ['127.0.0.1::3000']);
  assert.deepEqual(PORTS_BY_SERVICE.sphereon, ['127.0.0.1::8096']);
  assert.deepEqual(PORTS_BY_SERVICE['waltid-issuer'], ['127.0.0.1::7002']);
  assert.deepEqual(PORTS_BY_SERVICE['waltid-verifier'], ['127.0.0.1::7003']);
  assert.deepEqual(PORTS_BY_SERVICE['waltid-tls-proxy'], ['127.0.0.1::8097', '127.0.0.1::8098']);
  assert.deepEqual(PORTS_BY_SERVICE['ebsi-proxy'], ['127.0.0.1::8095']);
});

/** `pairs.json` でホスト経由の HTTP を話すピア（compose のサービスを指すもの）。 */
const HOST_PEERS = [
  ...PAIRS.uniformPeers,
  ...PAIRS.nativePeers,
  ...PAIRS.externalPrerequisitePeers,
  ...Object.values(PAIRS.didResolution.peers),
].filter((peer) => peer.service !== undefined);

test('pairs.json の service / containerPort が compose の公開と一致する', () => {
  assert.ok(HOST_PEERS.length > 0, 'service を持つピアが pairs.json に 1 件も無い');
  for (const peer of HOST_PEERS) {
    assert.ok(
      PORTS_BY_SERVICE[peer.service]?.includes(`127.0.0.1::${peer.containerPort}`),
      `${peer.service}:${peer.containerPort} を compose が公開していない`,
    );
  }
});

test('ホスト経由のピアは固定 baseUrl を持たない（実ポートへフォールバックさせない）', () => {
  for (const peer of HOST_PEERS) {
    assert.equal(peer.baseUrl, undefined, `${peer.service} に固定の baseUrl が残っている`);
  }
});
