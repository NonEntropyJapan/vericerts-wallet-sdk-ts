/**
 * JWT-VC / JWT-VP / Status List Token / 低レベル JWS 検証の high-S 受理マトリクス。
 *
 * - `ES256` は第三者 Issuer / HSM / KMS が返す high-S 署名を受理する（low-S も従来どおり受理）。
 * - `ES256K`（secp256k1）は high-S を従来と同じエラーコードで拒否し続ける。
 * - 署名は自前 signer の low-S 出力を `s → n - s` へ反転して作る（実鍵・モック禁止）。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../../../errors.js';
import { signStatusListToken } from '../../../../issuer/status-list-token.js';
import { verifyStatusListToken } from '../../../../issuer/status-list-token-verify.js';
import { sampleVp } from '../../../presentation/__tests__/presentation.fixtures.js';
import { issuePresentation } from '../../../presentation/issue.js';
import { verifyPresentation } from '../../../presentation/presentation.js';
import { issueCredential } from '../../issue.js';
import { decodeCompactJws, verifyWithJwk, verifyWithJwkOrFalse } from '../../jws.js';
import type { VerifiableCredential } from '../../vc.js';
import { verifyCredential } from '../../verify.js';
import { type EcdsaAlg, HIGH_S_FIXTURES, toHighS } from './high-s.fixtures.js';

const NOW = 1_767_225_600;
const ALGS: EcdsaAlg[] = ['ES256', 'ES256K'];

function codeOf(run: () => unknown): string | undefined {
  try {
    run();
  } catch (e) {
    expect(e).toBeInstanceOf(VericertsError);
    return (e as VericertsError).code;
  }
  return undefined;
}

function sampleVc(): VerifiableCredential {
  return {
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    type: ['VerifiableCredential'],
    issuer: 'did:example:issuer',
    credentialSubject: { id: 'did:example:subject', name: 'Alice' },
    issuanceDate: '2025-12-01T00:00:00Z',
    expirationDate: '2027-01-01T00:00:00Z',
    id: 'urn:uuid:high-s',
  };
}

describe.each(ALGS)('verifyWithJwk / verifyWithJwkOrFalse（%s）', (alg) => {
  const fx = HIGH_S_FIXTURES[alg];
  const jws = issueCredential(sampleVc(), fx.signer, { nowSeconds: NOW });

  it('low-S 署名は受理される', () => {
    expect(verifyWithJwk(alg, decodeCompactJws(jws), fx.jwk)).toBe(true);
  });

  it(`high-S 署名は ${alg === 'ES256' ? '受理' : '拒否'}される`, () => {
    const decoded = decodeCompactJws(toHighS(alg, jws));
    const expected = alg === 'ES256';
    expect(verifyWithJwk(alg, decoded, fx.jwk)).toBe(expected);
    expect(verifyWithJwkOrFalse(alg, decoded, fx.jwk)).toBe(expected);
  });
});

describe.each(ALGS)('JWT-VC verifyCredential（%s）', (alg) => {
  const fx = HIGH_S_FIXTURES[alg];
  const jws = issueCredential(sampleVc(), fx.signer, { nowSeconds: NOW });
  const opts = { key: { publicKeyJwk: fx.jwk }, nowSeconds: NOW } as const;

  it('low-S 署名は検証できる', () => {
    expect(verifyCredential(jws, opts).header.alg).toBe(alg);
  });

  if (alg === 'ES256') {
    it('high-S 署名も検証できる（第三者 Issuer / HSM 互換）', () => {
      const result = verifyCredential(toHighS(alg, jws), opts);
      expect((result.payload.vc as VerifiableCredential).credentialSubject.name).toBe('Alice');
    });
  } else {
    it('high-S 署名は SIG_INVALID（3010）で拒否される', () => {
      expect(codeOf(() => verifyCredential(toHighS(alg, jws), opts))).toBe(ErrorCodes.SIG_INVALID);
    });
  }
});

describe.each(ALGS)('JWT-VP verifyPresentation（%s）', (alg) => {
  const fx = HIGH_S_FIXTURES[alg];
  const jwt = issuePresentation(sampleVp(), fx.signer);
  const opts = { key: { publicKeyJwk: fx.jwk }, allowUnbound: true } as const;

  it('low-S 署名は検証できる', () => {
    expect(verifyPresentation(jwt, opts).payload.iss).toBe('did:example:holder');
  });

  if (alg === 'ES256') {
    it('high-S 署名も検証できる', () => {
      expect(verifyPresentation(toHighS(alg, jwt), opts).payload.iss).toBe('did:example:holder');
    });
  } else {
    it('high-S 署名は SIG_INVALID（3010）で拒否される', () => {
      expect(codeOf(() => verifyPresentation(toHighS(alg, jwt), opts))).toBe(
        ErrorCodes.SIG_INVALID,
      );
    });
  }
});

describe.each(ALGS)('Status List Token verifyStatusListToken（%s）', (alg) => {
  const fx = HIGH_S_FIXTURES[alg];
  const uri = 'https://issuer.example/status/1';
  const token = signStatusListToken(
    { issuer: 'did:web:issuer.example', uri, bits: 1, lst: 'eNpjYAAAAAIAAQ' },
    fx.signer,
    { iatSeconds: NOW },
  );

  it('low-S 署名は検証できる', () => {
    expect(verifyStatusListToken(token, uri, fx.jwk).iatSeconds).toBe(NOW);
  });

  if (alg === 'ES256') {
    it('high-S 署名も検証できる', () => {
      expect(verifyStatusListToken(toHighS(alg, token), uri, fx.jwk).iatSeconds).toBe(NOW);
    });
  } else {
    it('high-S 署名は SIG_INVALID（3010）で拒否される', () => {
      expect(codeOf(() => verifyStatusListToken(toHighS(alg, token), uri, fx.jwk))).toBe(
        ErrorCodes.SIG_INVALID,
      );
    });
  }
});
