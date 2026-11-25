// test/interop/__tests__/run-peer-matrix.native-verify.test.mjs
//
// native ピア検証の fail-closed 回帰テスト。4xx/5xx・非 JSON・checks 欠落の応答を
// pass 扱いにしないこと、および native 自己ペアが発行 VC の同ピア検証結果に従うことを固定する。
//
// 実行方法: リポジトリルートから
//   node --test test/interop/__tests__/run-peer-matrix.native-verify.test.mjs

import assert from 'node:assert/strict';
import test from 'node:test';
import {
  happyRoutes,
  jsonResponse,
  routedFetch,
  runWith,
  textResponse,
} from '../test-support/run-peer-matrix.fixtures.mjs';

test('regression: native ピアの検証が 4xx/5xx・非 JSON・checks 欠落の応答を返した場合は pass にせず fail にする', async () => {
  const cases = [
    {
      name: '502 HTML',
      res: () => textResponse(502, '<html>Bad Gateway</html>'),
      reason: /HTTP 502/,
    },
    {
      name: '404 message',
      res: () => jsonResponse(404, { message: 'not found' }),
      reason: /HTTP 404/,
    },
    { name: '200 HTML', res: () => textResponse(200, '<html>ok</html>'), reason: /JSON 以外/ },
    { name: '200 空オブジェクト', res: () => jsonResponse(200, {}), reason: /errors 配列が無い/ },
    {
      name: '200 checks 空',
      res: () => jsonResponse(200, { checks: [], warnings: [], errors: [] }),
      reason: /checks が無く/,
    },
  ];
  for (const { name, res, reason } of cases) {
    const routes = happyRoutes();
    routes['POST http://native-a.test/credentials/verify'] = res;

    const output = await runWith({ fetchImpl: routedFetch(routes) });

    const uniformToNative = output.results.find((r) => r.pair === 'interop:peerA:nativeA');
    assert.equal(uniformToNative.status, 'fail', name);
    assert.match(uniformToNative.reason, reason, name);
    const self = output.results.find((r) => r.pair === 'interop:nativeA:nativeA');
    assert.equal(self.status, 'fail', name);
    assert.match(self.reason, /^self-verify failed: /, name);
  }
});

test('regression: native 自己ペアは発行した VC を同ピアで検証し、その結果を pass/fail にマップする', async () => {
  const routes = happyRoutes();
  let verifiedBody;
  routes['POST http://native-a.test/credentials/verify'] = (options) => {
    verifiedBody = JSON.parse(options.body);
    return jsonResponse(200, { checks: ['proof'], warnings: [], errors: [] });
  };
  const output = await runWith({ fetchImpl: routedFetch(routes) });
  assert.deepEqual(
    output.results.find((r) => r.pair === 'interop:nativeA:nativeA'),
    { pair: 'interop:nativeA:nativeA', status: 'pass' },
  );
  assert.deepEqual(verifiedBody.verifiableCredential, { proof: {} });
});
