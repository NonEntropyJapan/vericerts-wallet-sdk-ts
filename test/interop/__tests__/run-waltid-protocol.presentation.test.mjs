// test/interop/__tests__/run-waltid-protocol.presentation.test.mjs
//
// `run-waltid-protocol.mjs` の Present フェーズが walt.id verifier に受理される形で提示することの回帰テスト。
// walt.id は Presentation Definition を `presentation_definition_uri` で参照として告知し、
// VP の署名検証で JWS ヘッダの `kid` から holder の鍵を解決する。実 HTTP 呼び出しはすべてモックする。
// 実行: `bun test test/interop/__tests__/run-waltid-protocol.presentation.test.mjs`

import { describe, expect, it } from 'bun:test';
import { fetchPresentationDefinition } from '../lib/waltid-verifier-session.mjs';
import { run } from '../run-waltid-protocol.mjs';

/** `Response` 互換の最小フィクスチャ。 */
function jsonResponse(body, { ok = true } = {}) {
  return { ok, status: ok ? 200 : 400, text: async () => JSON.stringify(body) };
}

const VALID_REQUEST_URI =
  'openid4vp://authorize' +
  '?response_type=vp_token' +
  `&client_id=${encodeURIComponent('https://verifier.example.test')}` +
  '&response_mode=direct_post' +
  `&response_uri=${encodeURIComponent('https://verifier.example.test/present')}` +
  '&nonce=test-nonce-0123456789abcdef' +
  '&state=test-state';

describe('run: walt.id verifier への提示', () => {
  it('presentation_definition_uri の定義を取得し、request.presentationDefinition に載せて送信する', async () => {
    const definition = { id: 'pd-1', input_descriptors: [{ id: 'OpenBadgeCredential' }] };
    const requestUri = `${VALID_REQUEST_URI}&presentation_definition_uri=${encodeURIComponent('https://verifier.example.test/pd/test-state')}`;
    const fetchedUrls = [];
    let submitted;
    const output = await run({
      fetchImpl: async (url) => {
        fetchedUrls.push(url);
        return jsonResponse(definition);
      },
      createIssuerOfferImpl: async () => ({
        offerUri: 'openid-credential-offer://fake',
        issuerPublicKeyJwk: { kty: 'OKP', crv: 'Ed25519', x: 'fake' },
      }),
      receiveCredentialImpl: async () => ({ raw: 'fake.jwt.vc' }),
      createVerifierRequestImpl: async () => requestUri,
      buildVPTokenImpl: () => 'fake-vp-token',
      submitPresentationImpl: async (request) => {
        submitted = request;
      },
      pollVerifierSessionImpl: async () => ({ verified: true }),
    });
    expect(fetchedUrls).toEqual(['https://verifier.example.test/pd/test-state']);
    expect(submitted.presentationDefinition).toEqual(definition);
    expect(output.results[1]).toEqual({
      pair: 'interop:vericerts:waltid-verifier',
      status: 'pass',
    });
  });

  // walt.id verifier は VP の署名検証で JWS ヘッダの `kid` から holder の鍵を解決する（無いと 400）。
  it('VP の署名鍵に kid（holder DID の検証メソッド id）を持たせる', async () => {
    let presented;
    await run({
      createIssuerOfferImpl: async () => ({
        offerUri: 'openid-credential-offer://fake',
        issuerPublicKeyJwk: { kty: 'OKP', crv: 'Ed25519', x: 'fake' },
      }),
      receiveCredentialImpl: async () => ({ raw: 'fake.jwt.vc' }),
      createVerifierRequestImpl: async () => VALID_REQUEST_URI,
      buildVPTokenImpl: (_request, presentations) => {
        presented = presentations[0];
        return 'fake-vp-token';
      },
      submitPresentationImpl: async () => undefined,
      pollVerifierSessionImpl: async () => ({ verified: true }),
    });
    expect(presented.signer.kid).toBe(
      `${presented.holder}#${presented.holder.slice('did:key:'.length)}`,
    );
  });
});

describe('fetchPresentationDefinition', () => {
  it('presentation_definition_uri が無い要求では取得せず undefined', async () => {
    const fetchImpl = async () => {
      throw new Error('呼ばれてはいけない');
    };
    expect(await fetchPresentationDefinition(VALID_REQUEST_URI, fetchImpl)).toBeUndefined();
  });

  it('非 2xx / id の無い応答は失敗にする', async () => {
    const requestUri = `${VALID_REQUEST_URI}&presentation_definition_uri=${encodeURIComponent('https://verifier.example.test/pd/x')}`;
    await expect(
      fetchPresentationDefinition(requestUri, async () =>
        jsonResponse({ error: 'x' }, { ok: false }),
      ),
    ).rejects.toThrow('presentation definition fetch failed');
    await expect(
      fetchPresentationDefinition(requestUri, async () => jsonResponse({ input_descriptors: [] })),
    ).rejects.toThrow('presentation definition fetch failed');
  });
});
