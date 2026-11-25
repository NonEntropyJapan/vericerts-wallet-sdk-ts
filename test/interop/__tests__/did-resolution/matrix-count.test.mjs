// DID 解決の公開 matrix 契約とランナーの結果を検証する。

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { run } from '../../run-did-resolution-matrix.mjs';
import { composePortStub, PAIRS, recordingFetch } from './fixtures.mjs';

const CONTRACT = JSON.parse(
  readFileSync(new URL('../../contracts/matrix.json', import.meta.url), 'utf8'),
).didResolution;

/** `pairs.json` の `didResolution.matrix` を同じ `"<method>:<peer>"` の配列にする。 */
function configMatrixCells() {
  return Object.entries(PAIRS.didResolution.matrix).flatMap(([method, peers]) =>
    peers.map((peer) => `${method}:${peer}`),
  );
}

test('公開 matrix 契約は 18 セルを持ち、pairs.json の DID 解決ペア数と一致する', () => {
  const count = Object.values(CONTRACT.matrix).flat().length;
  assert.equal(count, 18);
  assert.equal(configMatrixCells().length, count);
});

test('pairs.json の DID 解決ペアと厳格モードの条件は公開 matrix 契約と一致する', () => {
  const { matrix, structuralSkips, peers, fixtures } = PAIRS.didResolution;
  assert.deepEqual(matrix, CONTRACT.matrix);
  assert.deepEqual(
    structuralSkips.map(({ pair, reasonIncludes }) => ({ pair, reasonIncludes })),
    CONTRACT.structuralSkips,
  );
  for (const [name, peer] of Object.entries(peers)) {
    assert.equal(peer.resolveAccept, CONTRACT.resolveAccept[name], name);
  }
  for (const [method, fixture] of Object.entries(fixtures)) {
    assert.deepEqual(fixture.expectedKey, CONTRACT.expectedKeys[method], method);
  }
  assert.deepEqual(
    fixtures.ethr.eip1056Versions.map(({ version, registry, did }) => ({ version, registry, did })),
    CONTRACT.eip1056Versions,
  );
});

test('pairs.json の全ペアがランナーの結果にちょうど 1 回ずつ現れる', async () => {
  const { results } = await run({
    fetchImpl: recordingFetch(),
    spawnImpl: composePortStub(),
    env: {},
  });
  const pairs = results.map((r) => r.pair);
  assert.equal(new Set(pairs).size, pairs.length, `同一ペアの重複記録: ${pairs.join(', ')}`);
  assert.deepEqual(
    pairs.sort(),
    configMatrixCells()
      .map((cell) => `interop:did-resolve:${cell}`)
      .sort(),
  );
});
