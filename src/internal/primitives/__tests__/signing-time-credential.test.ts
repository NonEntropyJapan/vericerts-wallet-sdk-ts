/**
 * 署名側の時刻入力（`nowSeconds` / `now` / `iatSeconds` / 寿命）の fail-closed 検証。
 *
 * NaN / ±Infinity / 負値 / 文字列を渡すと、JSON 直列化で `iat: null` や `iat: "5"` の JWT が署名され、
 * 検証側が必ず弾く（または鮮度判定が成立しない）トークンに署名鍵を使うことになる。
 * 署名前に VericertsError で拒否し、署名が一度も呼ばれないことも確認する。
 */

import { describe, expect, it } from 'bun:test';
import { sampleVp } from '../../credential/presentation/__tests__/presentation.fixtures.js';
import { issuePresentation } from '../../credential/presentation/issue.js';
import { createKeyBindingTemplate } from '../../credential/sdjwt/key-binding.js';
import { createSdJwt } from '../../credential/sdjwt/sdjwt.js';
import { issueCredential } from '../../credential/vc/issue.js';
import { ErrorCodes } from '../../errors.js';
import { createDidJwt } from '../../identity/jwt/generate.js';
import { signStatusListToken } from '../../issuer/status-list-token.js';
import {
  BAD_LIFETIMES,
  BAD_TIMES,
  countingSigner,
  expectVericerts,
  NOW,
} from './signing-time.fixtures.js';

describe('署名側の時刻入力は署名前に拒否される（credential / identity）', () => {
  it('issueCredential / createSdJwt / issuePresentation: nowSeconds', () => {
    const { signer, calls } = countingSigner();
    const vc = {
      '@context': ['https://www.w3.org/ns/credentials/v2'],
      type: ['VerifiableCredential'],
      issuer: 'did:example:issuer',
      credentialSubject: { id: 'did:example:subject' },
      issuanceDate: '2026-01-01T00:00:00Z',
    };
    for (const nowSeconds of BAD_TIMES) {
      expectVericerts(() => issueCredential(vc, signer, { nowSeconds: nowSeconds as number }));
      expectVericerts(() =>
        createSdJwt(signer, {
          vct: 'https://example.com/credentials/identity',
          issuer: 'did:example:issuer',
          claims: { name: 'Alice' },
          disclosureClaims: ['name'],
          nowSeconds: nowSeconds as number,
        }),
      );
      expectVericerts(() =>
        issuePresentation(sampleVp(), signer, { nowSeconds: nowSeconds as number }),
      );
    }
    for (const expiresInSeconds of BAD_LIFETIMES) {
      expectVericerts(() =>
        issuePresentation(sampleVp(), signer, {
          nowSeconds: NOW,
          expiresInSeconds: expiresInSeconds as number,
        }),
      );
    }
    expect(calls()).toBe(0);
  });

  it('createDidJwt: iat / nbf / expiresInSeconds', () => {
    const privateKey = new Uint8Array(32).fill(7);
    for (const iat of BAD_TIMES) {
      expectVericerts(() => createDidJwt({ alg: 'ES256', privateKey, iat: iat as number }));
    }
    for (const nbf of BAD_TIMES) {
      expectVericerts(() =>
        createDidJwt({ alg: 'ES256', privateKey, iat: NOW, nbf: nbf as number }),
      );
    }
    for (const expiresInSeconds of BAD_LIFETIMES) {
      expectVericerts(() =>
        createDidJwt({
          alg: 'ES256',
          privateKey,
          iat: NOW,
          expiresInSeconds: expiresInSeconds as number,
        }),
      );
    }
  });

  it('signStatusListToken: iatSeconds', () => {
    const { signer, calls } = countingSigner();
    for (const iatSeconds of BAD_TIMES) {
      expectVericerts(
        () =>
          signStatusListToken(
            {
              issuer: 'did:example:issuer',
              uri: 'https://example.com/sl/1',
              bits: 1,
              lst: 'eNrbuRgAAhcBXQ',
            },
            signer,
            { iatSeconds: iatSeconds as number },
          ),
        ErrorCodes.VC_SCHEMA_INVALID,
      );
    }
    expect(calls()).toBe(0);
  });

  it('createKeyBindingTemplate: iatSeconds', () => {
    const { signer } = countingSigner();
    const sdJwt = createSdJwt(signer, {
      vct: 'https://example.com/credentials/identity',
      issuer: 'did:example:issuer',
      claims: { name: 'Alice' },
      disclosureClaims: ['name'],
    });
    for (const iatSeconds of BAD_TIMES) {
      expectVericerts(() =>
        createKeyBindingTemplate(sdJwt, {
          alg: 'ES256',
          nonce: 'n-1',
          audience: 'https://verifier.example',
          iatSeconds: iatSeconds as number,
        }),
      );
    }
  });

  it('正常な時刻入力は署名される（陽性対照）', () => {
    const { signer, calls } = countingSigner();
    expect(() =>
      createSdJwt(signer, {
        vct: 'https://example.com/credentials/identity',
        issuer: 'did:example:issuer',
        claims: { name: 'Alice' },
        disclosureClaims: ['name'],
        nowSeconds: NOW,
      }),
    ).not.toThrow();
    expect(() =>
      createDidJwt({ alg: 'ES256', privateKey: new Uint8Array(32).fill(7), iat: NOW }),
    ).not.toThrow();
    expect(() =>
      issuePresentation(sampleVp(), signer, { nowSeconds: NOW, expiresInSeconds: 300 }),
    ).not.toThrow();
    expect(calls()).toBeGreaterThan(0);
  });
});
