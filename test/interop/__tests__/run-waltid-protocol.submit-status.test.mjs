// test/interop/__tests__/run-waltid-protocol.submit-status.test.mjs
//
// `run-waltid-protocol.mjs` の Present フェーズが、VP Token 送信の失敗 reason に HTTP ステータスを添えることの
// 回帰テスト。SDK の `submitPresentation` は非 2xx・通信失敗・リダイレクトを
// すべて同じ 8035 に畳み、ステータスも応答本文も読まない。`pairs.json` の `knownIncompatible` が
// `VP Token の送信に失敗しました (HTTP 400)` だけを既知の非互換として扱い、5xx・通信失敗を
// 隠さないための前提になる。他の分岐は `run-waltid-protocol.test.mjs`。実行には Bun が必要。

import { describe, expect, it } from 'bun:test';
import { run } from '../run-waltid-protocol.mjs';

const VALID_REQUEST_URI =
  'openid4vp://authorize' +
  '?response_type=vp_token' +
  `&client_id=${encodeURIComponent('https://verifier.example.test')}` +
  '&response_mode=direct_post' +
  `&response_uri=${encodeURIComponent('https://verifier.example.test/present')}` +
  '&nonce=test-nonce-0123456789abcdef' +
  '&state=test-state';

const BASE = {
  createIssuerOfferImpl: async () => ({
    offerUri: 'openid-credential-offer://fake',
    issuerPublicKeyJwk: { kty: 'OKP', crv: 'Ed25519', x: 'fake' },
  }),
  receiveCredentialImpl: async () => ({ raw: 'fake.jwt.vc' }),
  createVerifierRequestImpl: async () => VALID_REQUEST_URI,
  buildVPTokenImpl: () => 'fake-vp-token',
};

describe('run: VP Token 送信失敗の reason に HTTP ステータスを添える', () => {
  it('送信が非 2xx で失敗したら reason に HTTP ステータスを添える', async () => {
    const output = await run({
      ...BASE,
      fetchImpl: async () => new Response('bad', { status: 400 }),
      // SDK の `submitPresentation` と同じく、渡された `fetchImpl` を呼んでから 8035 相当の例外を投げる。
      submitPresentationImpl: async (_request, _vpToken, options) => {
        await options.fetchImpl('https://verifier.example.test/present', { method: 'POST' });
        throw new Error('VP Token の送信に失敗しました');
      },
    });
    expect(output.results[1]).toEqual({
      pair: 'interop:vericerts:waltid-verifier',
      status: 'fail',
      reason: 'VP Token の送信に失敗しました (HTTP 400)',
    });
  });

  it('通信失敗（応答が無い）はステータスを添えない', async () => {
    const output = await run({
      ...BASE,
      fetchImpl: async () => {
        throw new TypeError('network down');
      },
      submitPresentationImpl: async (_request, _vpToken, options) => {
        try {
          await options.fetchImpl('https://verifier.example.test/present', { method: 'POST' });
        } catch {
          throw new Error('VP Token の送信に失敗しました');
        }
      },
    });
    expect(output.results[1]).toEqual({
      pair: 'interop:vericerts:waltid-verifier',
      status: 'fail',
      reason: 'VP Token の送信に失敗しました',
    });
  });
});
