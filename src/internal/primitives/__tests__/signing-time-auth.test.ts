/**
 * 署名側の時刻入力（`nowSeconds` / `now` / `iatSeconds` / 寿命）の fail-closed 検証。
 *
 * NaN / ±Infinity / 負値 / 文字列を渡すと、JSON 直列化で `iat: null` や `iat: "5"` の JWT が署名され、
 * 検証側が必ず弾く（または鮮度判定が成立しない）トークンに署名鍵を使うことになる。
 * 署名前に VericertsError で拒否し、署名が一度も呼ばれないことも確認する。
 */

import { describe, expect, it } from 'bun:test';
import { createDpopProof } from '../../auth/dpop/dpop.js';
import { generateProofJWT } from '../../auth/oid4vci/oid4vci.js';
import { generateIDToken } from '../../auth/siop/id-token.js';
import type { SIOPv2Request } from '../../auth/siop/types.js';
import { createSdJwt } from '../../credential/sdjwt/sdjwt.js';
import { ErrorCodes } from '../../errors.js';
import { issuePseudonymAttestation } from '../../eudi/pseudonym/attestation.js';
import { presentPseudonym } from '../../eudi/pseudonym/siop.js';
import { addKeyBindingWithTransactionData } from '../../eudi/transaction-data/hashes.js';
import {
  BAD_LIFETIMES,
  BAD_TIMES,
  countingSigner,
  expectVericerts,
  expectVericertsAsync,
  NOW,
  SEED,
} from './signing-time.fixtures.js';

describe('署名側の時刻入力は署名前に拒否される', () => {
  const request: SIOPv2Request = {
    clientId: 'https://rp.example.com',
    redirectUri: 'https://rp.example.com/cb',
    nonce: 'n-1',
    responseType: 'id_token',
    scope: 'openid',
  } as SIOPv2Request;

  it('generateIDToken: nowSeconds / lifetimeSeconds', async () => {
    const { signer, calls } = countingSigner();
    for (const nowSeconds of BAD_TIMES) {
      await expectVericertsAsync(() =>
        generateIDToken(request, 'did:key:z6MkHolder', signer, {
          nowSeconds: nowSeconds as number,
        }),
      );
    }
    for (const lifetimeSeconds of BAD_LIFETIMES) {
      await expectVericertsAsync(() =>
        generateIDToken(request, 'did:key:z6MkHolder', signer, {
          nowSeconds: NOW,
          lifetimeSeconds: lifetimeSeconds as number,
        }),
      );
    }
    expect(calls()).toBe(0);
  });

  it('presentPseudonym: nowSeconds / lifetimeSeconds', () => {
    const req = { clientId: 'rp-a.example', nonce: 'n-1' };
    for (const nowSeconds of BAD_TIMES) {
      expectVericerts(() =>
        presentPseudonym(req, 'rp-a.example', SEED, { nowSeconds: nowSeconds as number }),
      );
    }
    for (const lifetimeSeconds of BAD_LIFETIMES) {
      expectVericerts(() =>
        presentPseudonym(req, 'rp-a.example', SEED, {
          nowSeconds: NOW,
          lifetimeSeconds: lifetimeSeconds as number,
        }),
      );
    }
  });

  it('issuePseudonymAttestation: nowSeconds / lifetimeSeconds は生の RangeError ではなく VericertsError', () => {
    for (const nowSeconds of BAD_TIMES) {
      expectVericerts(() =>
        issuePseudonymAttestation('rp-a.example', SEED, {
          issuer: 'urn:wallet:test',
          nowSeconds: nowSeconds as number,
        }),
      );
    }
    for (const lifetimeSeconds of BAD_LIFETIMES) {
      expectVericerts(() =>
        issuePseudonymAttestation('rp-a.example', SEED, {
          issuer: 'urn:wallet:test',
          nowSeconds: NOW,
          lifetimeSeconds: lifetimeSeconds as number,
        }),
      );
    }
  });

  it('createDpopProof: nowSeconds', () => {
    const { signer, calls } = countingSigner();
    for (const nowSeconds of BAD_TIMES) {
      expectVericerts(
        () =>
          createDpopProof(
            { htm: 'POST', htu: 'https://as.example/token', nowSeconds: nowSeconds as number },
            signer,
          ),
        ErrorCodes.DPOP_PROOF_MALFORMED,
      );
    }
    expect(calls()).toBe(0);
  });

  it('generateProofJWT: now', () => {
    const { signer, calls } = countingSigner();
    for (const now of [...BAD_TIMES, -1000, Number.MAX_VALUE]) {
      expectVericerts(
        () =>
          generateProofJWT(
            {
              nonce: 'c-1',
              audience: 'https://issuer.example',
              issuer: 'did:example:holder',
              keyId: 'did:example:holder#k1',
              now: now as number,
            },
            signer,
          ),
        ErrorCodes.HOLDER_PROOF_INVALID,
      );
    }
    expect(calls()).toBe(0);
  });

  it('addKeyBindingWithTransactionData: iatSeconds', () => {
    const { signer, calls } = countingSigner();
    const sdJwt = createSdJwt(signer, {
      vct: 'https://example.com/credentials/identity',
      issuer: 'did:example:issuer',
      claims: { name: 'Alice' },
      disclosureClaims: ['name'],
    });
    const before = calls();
    for (const iatSeconds of BAD_TIMES) {
      expectVericerts(() =>
        addKeyBindingWithTransactionData(sdJwt, signer, {
          nonce: 'n-1',
          audience: 'https://verifier.example',
          transactionData: [{ type: 'payment', credential_ids: ['pid'] }] as never,
          iatSeconds: iatSeconds as number,
        }),
      );
    }
    expect(calls()).toBe(before);
  });
});
