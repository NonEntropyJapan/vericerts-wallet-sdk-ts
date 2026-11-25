/**
 * SD-JWT VC（Issuer-signed JWT）/ KB-JWT の high-S 受理マトリクス。
 *
 * ES256 は high-S を受理し、ES256K は従来のコード（Issuer 署名 3010 / KB-JWT 3012）で拒否し続ける。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../../../errors.js';
import { createSdJwt, selectDisclosures } from '../../../sdjwt/sdjwt.js';
import { addKeyBinding, verifySdJwt } from '../../../sdjwt/verify.js';
import { createPrivateKeySigner } from '../../signer.js';
import { type EcdsaAlg, HIGH_S_FIXTURES, toHighS } from './high-s.fixtures.js';

const VCT = 'https://example.com/credentials/identity';
const AUD = 'https://verifier.example';
const NONCE = 'verifier-nonce-3873';
const IAT = 1_767_225_600;
const ALGS: EcdsaAlg[] = ['ES256', 'ES256K'];
/** KB-JWT を署名する Holder 鍵（Issuer と別鍵）。 */
const HOLDER_KEY = new Uint8Array(32).fill(57);

function codeOf(run: () => unknown): string | undefined {
  try {
    run();
  } catch (e) {
    expect(e).toBeInstanceOf(VericertsError);
    return (e as VericertsError).code;
  }
  return undefined;
}

/** `jwt~disclosure~...~[kb]` の指定位置（0 始まり）の JWS を high-S に書き換える。 */
function rewriteSegment(alg: EcdsaAlg, sdJwt: string, index: number): string {
  const parts = sdJwt.split('~');
  parts[index] = toHighS(alg, parts[index] ?? '');
  return parts.join('~');
}

describe.each(ALGS)('SD-JWT VC Issuer-signed JWT（%s）', (alg) => {
  const fx = HIGH_S_FIXTURES[alg];
  const sdJwt = createSdJwt(fx.signer, {
    vct: VCT,
    issuer: 'did:example:issuer',
    disclosureClaims: ['name'],
    claims: { name: 'Alice' },
    salts: { name: 'salt-name' },
  });
  const opts = { issuerKey: fx.jwk, expectedVct: VCT } as const;

  it('low-S 署名は検証できる', () => {
    expect(verifySdJwt(sdJwt, opts).claims.name).toBe('Alice');
  });

  if (alg === 'ES256') {
    it('high-S 署名も検証できる', () => {
      expect(verifySdJwt(rewriteSegment(alg, sdJwt, 0), opts).claims.name).toBe('Alice');
    });
  } else {
    it('high-S 署名は SIG_INVALID（3010）で拒否される', () => {
      expect(codeOf(() => verifySdJwt(rewriteSegment(alg, sdJwt, 0), opts))).toBe(
        ErrorCodes.SIG_INVALID,
      );
    });
  }
});

describe.each(ALGS)('KB-JWT（%s）', (alg) => {
  const fx = HIGH_S_FIXTURES[alg];
  const holder = createPrivateKeySigner(HOLDER_KEY, alg);
  const sdJwt = createSdJwt(fx.signer, {
    vct: VCT,
    issuer: 'did:example:issuer',
    cnf: { jwk: holder.publicKeyJwk },
    disclosureClaims: ['name'],
    claims: { name: 'Alice' },
    salts: { name: 'salt-name' },
    nowSeconds: IAT,
  });
  const bound = addKeyBinding(selectDisclosures(sdJwt, ['name']), holder, {
    nonce: NONCE,
    audience: AUD,
    iatSeconds: IAT,
  });
  /** KB-JWT は `~` 区切りの最終セグメント。 */
  const kbIndex = bound.split('~').length - 1;
  const opts = {
    issuerKey: fx.jwk,
    audience: AUD,
    nonce: NONCE,
    requireKeyBinding: true,
    nowSeconds: IAT,
  } as const;

  it('low-S の KB-JWT は検証できる', () => {
    expect(verifySdJwt(bound, opts).keyBindingVerified).toBe(true);
  });

  if (alg === 'ES256') {
    it('high-S の KB-JWT も検証できる', () => {
      expect(verifySdJwt(rewriteSegment(alg, bound, kbIndex), opts).keyBindingVerified).toBe(true);
    });
  } else {
    it('high-S の KB-JWT は HOLDER_BIND_MISMATCH（3012）で拒否される', () => {
      expect(codeOf(() => verifySdJwt(rewriteSegment(alg, bound, kbIndex), opts))).toBe(
        ErrorCodes.HOLDER_BIND_MISMATCH,
      );
    });
  }
});
