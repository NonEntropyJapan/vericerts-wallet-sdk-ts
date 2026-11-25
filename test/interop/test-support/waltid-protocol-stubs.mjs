// test/interop/test-support/waltid-protocol-stubs.mjs
//
// `__tests__/run-waltid-protocol.test.mjs` の `fetchImpl` スタブと妥当な request URI（外部 I/O はすべてモック）。
// テスト本体と分けたのは、linterly の 1 ファイル / ディレクトリの行数上限に収めるため。検証内容はテスト側に残している。
// `*.test.mjs` ではないので単独では実行されない。

/** `Response` 互換の最小フィクスチャ。 */
export function jsonResponse(body, { ok = true, status = ok ? 200 : 400 } = {}) {
  return {
    ok,
    status,
    text: async () => (typeof body === 'string' ? body : JSON.stringify(body)),
  };
}

/** 呼び出しごとに `responses` を順番に返す `fetchImpl` スタブ。 */
export function sequenceFetch(responses) {
  let index = 0;
  return async () => {
    if (index >= responses.length) {
      throw new Error(`sequenceFetch: 想定より多く呼び出された (呼び出し ${index + 1} 回目)`);
    }
    const response = responses[index];
    index += 1;
    return response;
  };
}

export const VALID_REQUEST_URI =
  'openid4vp://authorize' +
  '?response_type=vp_token' +
  `&client_id=${encodeURIComponent('https://verifier.example.test')}` +
  '&response_mode=direct_post' +
  `&response_uri=${encodeURIComponent('https://verifier.example.test/present')}` +
  // SDK は nonce 22 文字未満（128 bit 未満）を拒否する（MIN_NONCE_LENGTH）。
  '&nonce=test-nonce-0123456789abcdef' +
  '&state=test-state';
