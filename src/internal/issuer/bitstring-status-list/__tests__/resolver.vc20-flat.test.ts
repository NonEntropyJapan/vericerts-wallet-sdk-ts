/**
 * Bitstring Status List の検証が、VC 2.0 系（`vc` 非包み）の署名済みトークンを構造不正（3002）で拒否すること
 * `verifyCredential` は 2 表現を通すようになったが、リスト VC は本 SDK が
 * 発行する `vc` claim の形だけを扱う。ここで落とさないと、署名が有効なのに 3010（署名不正）に見える。
 * 他の検証は `resolver.test.ts`。
 */

import { describe, expect, it } from 'bun:test';
import { base64urlnopad } from '@scure/base';
import { createPrivateKeySigner } from '../../../credential/vc/signer.js';
import { ErrorCodes, type VericertsError } from '../../../errors.js';
import type { PublicKeyJwk } from '../../../identity/did.js';
import { getP256PublicKey } from '../../../keymanager/signer.js';
import { verifyBitstringStatusListCredential } from '../index.js';

const URL1 = 'https://issuer.example/status/1';
const ISSUER = 'did:web:issuer.example';
const IAT = 1_767_224_600;
const KEY = new Uint8Array(32).fill(9);
const SIGNER = createPrivateKeySigner(KEY, 'ES256');
const pub = getP256PublicKey(KEY, false);
const b64u = (b: Uint8Array): string => Buffer.from(b).toString('base64url');
const ISSUER_JWK: PublicKeyJwk = {
  kty: 'EC',
  crv: 'P-256',
  x: b64u(pub.subarray(1, 33)),
  y: b64u(pub.subarray(33, 65)),
};

describe('verifyBitstringStatusListCredential: VC 2.0 系（vc 非包み）', () => {
  it('署名済みでも 3002（署名不正の 3010 に化けない）', async () => {
    const text = (value: unknown): string =>
      Buffer.from(JSON.stringify(value)).toString('base64url');
    const signingInput = `${text({ alg: 'ES256', typ: 'JWT' })}.${text({
      iss: ISSUER,
      '@context': ['https://www.w3.org/ns/credentials/v2'],
      id: URL1,
      type: ['VerifiableCredential', 'BitstringStatusListCredential'],
      issuer: ISSUER,
      credentialSubject: { id: `${URL1}#list`, type: 'BitstringStatusList' },
      validFrom: '2025-12-31T23:43:20Z',
      jti: URL1,
      nbf: IAT,
    })}`;
    const jwt = `${signingInput}.${base64urlnopad.encode(SIGNER.sign(new TextEncoder().encode(signingInput)))}`;

    let code = 'no error';
    try {
      await verifyBitstringStatusListCredential(jwt, URL1, {
        key: { publicKeyJwk: ISSUER_JWK },
        nowSeconds: IAT + 100,
      });
    } catch (e) {
      code = (e as VericertsError).code;
    }
    expect(code).toBe(ErrorCodes.VC_SCHEMA_INVALID);
  });
});
