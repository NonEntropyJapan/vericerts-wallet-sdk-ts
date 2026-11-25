// test/interop/__tests__/wait-peers-healthy.test.mjs
//
// interop-nightly の peer healthy 待機判定の回帰テスト。停止・クラッシュした peer や
// 空の一覧を「全 peer healthy」と誤判定しないことを固定する。
//
// 実行方法: node --test test/interop/__tests__/wait-peers-healthy.test.mjs

import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { findUnhealthyPeers, parsePsOutput } from '../wait-peers-healthy.mjs';

const SCRIPT = fileURLToPath(new URL('../wait-peers-healthy.mjs', import.meta.url));
const svc = (Service, State, Health) => ({ Service, State, Health });

test('regression: 全 peer が running かつ healthy なら不健全 0 件', () => {
  const services = [svc('vericerts', 'running', 'healthy'), svc('didkit', 'running', 'healthy')];
  assert.deepEqual(findUnhealthyPeers(services), []);
});

test('regression: 停止・クラッシュした peer（State=exited）は healthy 扱いにしない', () => {
  const unhealthy = findUnhealthyPeers([
    svc('vericerts', 'running', 'healthy'),
    svc('didkit', 'exited', ''),
  ]);
  assert.equal(unhealthy.length, 1);
  assert.match(unhealthy[0], /didkit/);
});

test('regression: starting / unhealthy / healthcheck 無し（Health 空）は不健全', () => {
  const unhealthy = findUnhealthyPeers([
    svc('a', 'running', 'starting'),
    svc('b', 'running', 'unhealthy'),
    svc('c', 'running', ''),
  ]);
  assert.equal(unhealthy.length, 3);
});

test('regression: コンテナが 1 つも列挙されない（全 peer が一覧から消えた）場合は不健全', () => {
  assert.deepEqual(findUnhealthyPeers([]), ['no peer containers found']);
  assert.deepEqual(findUnhealthyPeers([svc('ebsi-proxy', 'running', '')]), [
    'no peer containers found',
  ]);
});

test('regression: 外部前提 peer（ebsi-proxy）は停止していても待機対象にしない', () => {
  const services = [svc('vericerts', 'running', 'healthy'), svc('ebsi-proxy', 'exited', '')];
  assert.deepEqual(findUnhealthyPeers(services), []);
});

test('NDJSON と JSON 配列の両方の docker compose ps 出力を解釈する', () => {
  const rows = [svc('a', 'running', 'healthy'), svc('b', 'exited', '')];
  assert.deepEqual(parsePsOutput(rows.map((r) => JSON.stringify(r)).join('\n')), rows);
  assert.deepEqual(parsePsOutput(JSON.stringify(rows)), rows);
  assert.deepEqual(parsePsOutput('  \n'), []);
});

test('regression: CLI は空入力・不健全で exit 1、全 healthy で exit 0', () => {
  const run = (input) => spawnSync(process.execPath, [SCRIPT], { input, encoding: 'utf8' });
  assert.equal(run('').status, 1);
  assert.equal(run(JSON.stringify(svc('a', 'exited', ''))).status, 1);
  assert.equal(run('not json').status, 1);
  assert.equal(run(JSON.stringify(svc('a', 'running', 'healthy'))).status, 0);
});
