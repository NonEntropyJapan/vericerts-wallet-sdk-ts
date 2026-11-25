/**
 * `didDocumentToVerifierKey` の VerificationMethod 鍵メンバ読みの prototype 汚染耐性。
 *
 * `createDidKey` が返す生成オブジェクトは通常プロトタイプのため、`vm.publicKeyJwk` を鎖読みすると
 * `Object.prototype.publicKeyJwk` 汚染で本来の `publicKeyMultibase` より攻撃者の JWK が優先される。
 */

import { describe, expect, it } from 'bun:test';
import { withPollutedPrototype } from '../../../../__tests__/prototype-pollution.fixtures.js';
import { ErrorCodes, VericertsError } from '../../../../errors.js';
import { createDidKey } from '../../../../identity/method-key.js';
import { getEd25519PublicKey } from '../../../../keymanager/ed25519.js';
import { didDocumentToVerifierKey } from '../../verifier-key.js';

const ISSUER_KEY = getEd25519PublicKey(new Uint8Array(32).fill(3));
const ATTACKER_KEY = getEd25519PublicKey(new Uint8Array(32).fill(9));
const b64u = (bytes: Uint8Array): string => Buffer.from(bytes).toString('base64url');

function keyJwkOf(): { x?: string } {
  const key = didDocumentToVerifierKey(createDidKey('Ed25519', ISSUER_KEY));
  return (key as { publicKeyJwk: { x?: string } }).publicKeyJwk;
}

describe('verificationMethodToJwk の鍵メンバは own 限定', () => {
  it('Object.prototype.publicKeyJwk を汚染しても did:key の元の鍵が返る', () => {
    const clean = keyJwkOf().x;
    expect(clean).toBe(b64u(ISSUER_KEY));
    const polluted = withPollutedPrototype(
      { publicKeyJwk: { kty: 'OKP', crv: 'Ed25519', x: b64u(ATTACKER_KEY) } },
      () => keyJwkOf().x,
    );
    expect(polluted).toBe(clean);
  });

  it('publicKeyMultibase 汚染では鍵が得られず（鍵なし VM）2010 のまま', () => {
    const doc = createDidKey('Ed25519', ISSUER_KEY);
    const vm = (doc.verificationMethod ?? [])[0];
    expect(vm).toBeDefined();
    const bare = { id: vm?.id ?? '', type: 'Multikey', controller: doc.id };
    const withoutKey = { ...doc, verificationMethod: [bare], assertionMethod: [bare.id] };
    let caught: unknown;
    withPollutedPrototype({ publicKeyMultibase: 'z6MkAttacker', publicKeyHex: '00' }, () => {
      try {
        didDocumentToVerifierKey(withoutKey as never);
      } catch (error) {
        caught = error;
      }
    });
    expect(caught).toBeInstanceOf(VericertsError);
    expect((caught as VericertsError).code).toBe(ErrorCodes.DID_DOC_INVALID);
  });

  it('JWK メンバ x の汚染で欠落メンバを補えない（own 読み）', () => {
    const doc = createDidKey('Ed25519', ISSUER_KEY);
    const vm = (doc.verificationMethod ?? [])[0];
    const jwkNoX = { kty: 'OKP', crv: 'Ed25519' };
    const bare = {
      id: vm?.id ?? '',
      type: 'JsonWebKey2020',
      controller: doc.id,
      publicKeyJwk: jwkNoX,
    };
    const crafted = { ...doc, verificationMethod: [bare], assertionMethod: [bare.id] };
    let caught: unknown;
    withPollutedPrototype({ x: b64u(ATTACKER_KEY) }, () => {
      try {
        didDocumentToVerifierKey(crafted as never);
      } catch (error) {
        caught = error;
      }
    });
    expect(caught).toBeInstanceOf(VericertsError);
    expect((caught as VericertsError).code).toBe(ErrorCodes.DID_DOC_INVALID);
  });
});
