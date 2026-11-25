/**
 * did:ebsi の単体テスト共通フィクスチャ。
 */

import { p256Jwk, secp256k1Jwk } from '../../__tests__/network-method.fixtures.js';
import type { DIDDocument } from '../../did.js';

export const API_URL = 'https://api-pilot.ebsi.example.org';
export const DID = 'did:ebsi:zvHWX359A3CvfJnCYaAiAde';

/** EBSI の法人 DID 文書（ES256 の assertionMethod と ES256K の capabilityInvocation）。 */
export function ebsiDocument(
  did: string = DID,
  overrides: Record<string, unknown> = {},
): DIDDocument {
  return {
    '@context': ['https://www.w3.org/ns/did/v1', 'https://w3id.org/security/suites/jws-2020/v1'],
    id: did,
    controller: [did],
    verificationMethod: [
      { id: `${did}#es256`, type: 'JsonWebKey2020', controller: did, publicKeyJwk: p256Jwk() },
      {
        id: `${did}#es256k`,
        type: 'JsonWebKey2020',
        controller: did,
        publicKeyJwk: secp256k1Jwk(),
      },
    ],
    authentication: [`${did}#es256`],
    assertionMethod: [`${did}#es256`],
    capabilityInvocation: [`${did}#es256k`],
    ...overrides,
  } as unknown as DIDDocument;
}
