// test/interop/__tests__/sd-jwt/fixtures.mjs
//
// `sd-jwt/*.test.mjs` 共通のペア名と依存スタブ（walt.id への実 HTTP 呼び出しはすべてモック）。
// 実ピアを起動せずに run-waltid-sdjwt.mjs のプロトコル分岐を駆動する。

export const PAIR_ISSUE = 'interop:waltid-issuer:vericerts:sd-jwt';
export const PAIR_PRESENT = 'interop:vericerts:waltid-verifier:sd-jwt';

/**
 * walt.id が credential configuration に対して告知する `vct`。
 *
 * walt.id は `baseUrl` を前置した値を告知し、発行要求で渡した `credentialData.vct` は無視する。
 * 値がホスト・ポートに依存するため `pairs.json` には持たせず、実行時に告知から取る。
 */
export const ADVERTISED_VCT = 'https://issuer.interop.example/draft13/identity_credential';

/** 公開ホスト検査を通る Authorization Request（`response_uri` が公開 FQDN）。 */
export const VALID_REQUEST_URI =
  'openid4vp://authorize' +
  '?response_type=vp_token' +
  `&client_id=${encodeURIComponent('https://verifier.example.test')}` +
  '&response_mode=direct_post' +
  `&response_uri=${encodeURIComponent('https://verifier.example.test/present')}` +
  // SDK は nonce 22 文字未満（128 bit 未満）を拒否する（MIN_NONCE_LENGTH）。
  '&nonce=test-nonce-0123456789abcdef' +
  '&state=test-state';

/** `response_uri` を loopback（公開ホスト検査で拒否される）に差し替えた要求。 */
export const LOOPBACK_RESPONSE_URI_REQUEST = VALID_REQUEST_URI.replace(
  encodeURIComponent('https://verifier.example.test/present'),
  encodeURIComponent('https://localhost:8098/present'),
);

/**
 * 実ピアへ出ていかない依存一式。各テストは検証したい分岐だけを上書きする。
 *
 * `receivedOptions` に `receiveCredentialImpl` が受け取ったオプションを積む。
 */
export function deps(overrides = {}, receivedOptions = []) {
  return {
    pairSuffix: '',
    createIssuerOfferImpl: async () => ({
      offerUri: `openid-credential-offer://?credential_offer_uri=${encodeURIComponent(
        'https://issuer.interop.example/draft13/credentialOffer?id=abc',
      )}`,
      issuerPublicKeyJwk: { kty: 'OKP', crv: 'Ed25519', x: 'fake' },
      // walt.id が告知する `vct`。発行要求で渡した値ではなく、これが受領後の照合と提示要求に使われる。
      vct: ADVERTISED_VCT,
    }),
    // 受領オプション（`format` / `verifyReceived`）を記録する。捨てると、ドライバが
    // `dc+sd-jwt` を送っていることも告知 `vct` で照合していることもテストで見えない。
    receiveCredentialImpl: async (_offerUri, options) => {
      receivedOptions.push(options);
      return { raw: 'issuer.jwt.sd~disclosure~' };
    },
    verifySdJwtImpl: () => ({ claims: {} }),
    createVerifierRequestImpl: async () => VALID_REQUEST_URI,
    fetchPresentationDefinitionImpl: async () => ({
      id: 'definition-1',
      input_descriptors: [{ id: 'interop-sd-jwt' }],
    }),
    buildVPTokenImpl: () => 'issuer.jwt.sd~disclosure~kb.jwt.sig',
    submitPresentationImpl: async () => undefined,
    pollVerifierSessionImpl: async () => ({ verified: true }),
    ...overrides,
  };
}
