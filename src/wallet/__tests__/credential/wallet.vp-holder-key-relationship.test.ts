/**
 * JWT-VP の holder 署名鍵は `authentication` で解決する。
 *
 * W3C VC Data Model v2.0 / DID Core では holder の本人認証は `authentication` の検証方法で行う。
 * VC 署名用の `assertionMethod` にだけ宣言された鍵（did:ethr `veriKey` 委任鍵など）で署名した VP を
 * holder として受理すると、「credential 署名のみ許された鍵」が holder になりすませる。
 * 逆に `authentication` にだけ宣言された鍵（did:ethr `sigAuth`）で署名した正当な VP は受理される。
 * VC 自体の発行者鍵は引き続き `assertionMethod` で解決する。
 */

import { describe, expect, it } from 'bun:test';
import { issueCredential } from '../../../internal/credential/index.js';
import { issuePresentation } from '../../../internal/credential/presentation/issue.js';
import { createPrivateKeySigner } from '../../../internal/credential/vc/signer.js';
import { ErrorCodes, VericertsError } from '../../../internal/errors.js';
import { resolvePresentationEnvelope } from '../../credential/presentation-envelope.js';
import { resolveIssuerVerifierKey } from '../../issuer-key.js';

const HOLDER = 'did:example:holder';
const controllerSigner = createPrivateKeySigner(new Uint8Array(32).fill(1), 'ES256');
const delegateSigner = createPrivateKeySigner(new Uint8Array(32).fill(2), 'ES256');

const DOC = {
  '@context': ['https://www.w3.org/ns/did/v1'],
  id: HOLDER,
  verificationMethod: [
    {
      id: `${HOLDER}#controller`,
      type: 'JsonWebKey2020',
      controller: HOLDER,
      publicKeyJwk: controllerSigner.publicKeyJwk,
    },
    {
      id: `${HOLDER}#delegate-1`,
      type: 'JsonWebKey2020',
      controller: HOLDER,
      publicKeyJwk: delegateSigner.publicKeyJwk,
    },
  ],
  authentication: [`${HOLDER}#controller`],
  assertionMethod: [`${HOLDER}#delegate-1`],
};

const resolver = { resolve: async () => DOC } as never;
const metrics = new Proxy({}, { get: () => () => undefined }) as never;
const VP = {
  '@context': ['https://www.w3.org/ns/credentials/v2'],
  type: ['VerifiablePresentation'],
  holder: HOLDER,
  verifiableCredential: ['x.y.z'],
};

function signVp(signer: typeof controllerSigner, kid?: string): string {
  const withKid = kid === undefined ? signer : { ...signer, kid: `${HOLDER}${kid}` };
  return issuePresentation(
    VP as never,
    withKid as never,
    {
      audience: 'aud',
      nonce: 'n',
    } as never,
  );
}

const opts = { expectedAudience: 'aud', expectedNonce: 'n' } as never;

describe('JWT-VP holder 署名鍵の用途分離', () => {
  it('authentication にだけ宣言された鍵で署名した VP は受理される', async () => {
    const r = await resolvePresentationEnvelope(resolver, signVp(controllerSigner), metrics, opts);
    expect(r.claims.asserted.holder).toBe(HOLDER);
  });

  it('kid が authentication の鍵を指す VP も受理される', async () => {
    const r = await resolvePresentationEnvelope(
      resolver,
      signVp(controllerSigner, '#controller'),
      metrics,
      opts,
    );
    expect(r.claims.asserted.holder).toBe(HOLDER);
  });

  it('kid が assertionMethod 専用鍵を指す VP は 2010 で拒否される（鍵選択の候補外）', async () => {
    await expect(
      resolvePresentationEnvelope(resolver, signVp(delegateSigner, '#delegate-1'), metrics, opts),
    ).rejects.toThrow(new VericertsError(ErrorCodes.DID_DOC_INVALID));
  });

  it('kid 無しで assertionMethod 専用鍵が署名した VP は 3010 で拒否される', async () => {
    await expect(
      resolvePresentationEnvelope(resolver, signVp(delegateSigner), metrics, opts),
    ).rejects.toThrow(new VericertsError(ErrorCodes.SIG_INVALID));
  });

  it('VC の発行者鍵は引き続き assertionMethod で解決される', async () => {
    const jwt = issueCredential(
      {
        '@context': ['https://www.w3.org/ns/credentials/v2'],
        type: ['VerifiableCredential'],
        issuer: HOLDER,
        credentialSubject: { id: HOLDER },
        issuanceDate: '2025-01-01T00:00:00Z',
      } as never,
      delegateSigner as never,
      { kid: `${HOLDER}#delegate-1` } as never,
    );
    const key = await resolveIssuerVerifierKey(resolver, jwt);
    expect(key.publicKeyJwk).toEqual(delegateSigner.publicKeyJwk);
  });
});
