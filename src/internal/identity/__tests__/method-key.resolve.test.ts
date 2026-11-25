/**
 * resolveDidKey の解決検証。
 *
 * Ed25519 W3C ベクターを解決し、DID Document の全フィールドが期待値と一致することを確認する。
 */

import { describe, expect, it } from 'bun:test';
import { resolveDidKey } from '../method-key.js';

/** W3C did:key Method spec の Ed25519 Test Vector DID。 */
const W3C_ED25519_DID = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK';
/** DID の `did:key:` を除いた multibase 部分。 */
const KEY_ID = 'z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK';

describe('resolveDidKey', () => {
  it('Ed25519 W3C ベクターを期待 DID Document に解決する', () => {
    const doc = resolveDidKey(W3C_ED25519_DID);
    expect(doc).toEqual({
      '@context': ['https://www.w3.org/ns/did/v1'],
      id: W3C_ED25519_DID,
      verificationMethod: [
        {
          id: `${W3C_ED25519_DID}#${KEY_ID}`,
          type: 'Ed25519VerificationKey2020',
          controller: W3C_ED25519_DID,
          publicKeyMultibase: KEY_ID,
        },
      ],
      authentication: [`${W3C_ED25519_DID}#${KEY_ID}`],
      assertionMethod: [`${W3C_ED25519_DID}#${KEY_ID}`],
    });
  });
});
