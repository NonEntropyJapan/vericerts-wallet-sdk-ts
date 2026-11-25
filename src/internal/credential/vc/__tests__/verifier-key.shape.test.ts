/**
 * `didDocumentToVerifierKey` の欠落・非配列・deactivated ガード。
 *
 * ネットワーク由来の DID Document は配列を欠く、または配列でない値を載せ得る。
 * 素の `assertionMethod[0]` / `verificationMethod.find` は生 TypeError になる。
 * `deactivated: true` の文書は委任鍵が残っていても検証鍵にしない。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import type { DIDDocument } from '../../../identity/did.js';
import { didDocumentToVerifierKey } from '../verifier-key.js';

const DID = 'did:example:issuer';

function doc(partial: Record<string, unknown>): DIDDocument {
  return {
    '@context': ['https://www.w3.org/ns/did/v1'],
    id: DID,
    ...partial,
  } as unknown as DIDDocument;
}

const vm = {
  id: `${DID}#delegate-1`,
  type: 'JsonWebKey2020',
  controller: DID,
  publicKeyJwk: { kty: 'OKP', crv: 'Ed25519', x: 'aaaa' },
};

describe('didDocumentToVerifierKey の形状と deactivated', () => {
  it('assertionMethod / verificationMethod 欠落は生 TypeError ではなく 2010', () => {
    expect(() => didDocumentToVerifierKey(doc({}))).toThrow(
      new VericertsError(ErrorCodes.DID_DOC_INVALID),
    );
  });

  it('verificationMethod が配列でないときは 2010', () => {
    expect(() =>
      didDocumentToVerifierKey(doc({ verificationMethod: 'oops', assertionMethod: 7 })),
    ).toThrow(new VericertsError(ErrorCodes.DID_DOC_INVALID));
  });

  it('deactivated の文書は指定した委任鍵でも 2010', () => {
    expect(() =>
      didDocumentToVerifierKey(
        doc({
          verificationMethod: [vm],
          assertionMethod: [`${DID}#delegate-1`],
          deactivated: true,
        }),
        { verificationMethodId: `${DID}#delegate-1` },
      ),
    ).toThrow(new VericertsError(ErrorCodes.DID_DOC_INVALID));
  });
});
