/**
 * SD-JWT VC を内包する VP の検証が、VP 側の `issuerTrust`（FC-11）・`nowSeconds`・
 * `clockSkewSeconds` を内包 VC の検証へ中継することの回帰テスト。
 *
 * JWT-VC 経路は `presentation.credential-results.formats.test.ts` が固定しているが、SD-JWT VC 経路
 * （`sd-jwt-vc-entry.ts` の `...delegatedOptions(input)`）は未固定で、削除しても全テストが通っていた。
 * 実鍵のみを使う。
 */

import { describe, expect, it } from 'bun:test';
import {
  AFTER_REVOKED,
  BEFORE_REVOKED,
  declaration,
  NOW as FC11_NOW,
  ISSUER_ID,
  ISSUER_JWK,
  issueSdJwtVc,
  SIGNING_KID,
  trustChain,
} from '../../__tests__/issuer-key-revocation/issuer-key-revocation.fixtures.js';
import { createSdJwt } from '../../sdjwt/sdjwt.js';
import type { EmbeddedCredentialKeyResolver } from '../credential-results.js';
import { issuePresentation } from '../issue.js';
import { verifyPresentation } from '../presentation.js';
import { FIXTURES, sampleVp, signerFor } from './presentation.fixtures.js';

const HOLDER_ALG = 'ES256' as const;
const ISSUER_ALG = 'ES256K' as const;
/** 実時計より十分過去の基準時刻。中継が落ちて実時計で評価されると結果が変わる。 */
const PAST = 1_600_000_000;
const VCT = 'https://example.com/credentials/identity';

const holderKey = { key: { publicKeyJwk: FIXTURES[HOLDER_ALG].jwk }, allowUnbound: true } as const;

function vpWith(entry: string, nowSeconds: number): string {
  return issuePresentation(sampleVp({ verifiableCredential: [entry] }), signerFor(HOLDER_ALG), {
    nowSeconds,
  });
}

/** `exp` / `iat` を指定した SD-JWT VC（ES256K 発行者鍵）。 */
function sdJwtWith(claims: Record<string, unknown>): string {
  return createSdJwt(signerFor(ISSUER_ALG), {
    vct: VCT,
    issuer: 'did:example:issuer',
    disclosureClaims: ['name'],
    claims: { name: 'Alice', ...claims },
    salts: { name: 'salt-name' },
    nowSeconds: PAST,
  });
}

const issuerKeyResolver: EmbeddedCredentialKeyResolver = () => ({
  publicKeyJwk: FIXTURES[ISSUER_ALG].jwk,
});

describe('内包 SD-JWT VC への issuerTrust 中継（FC-11）', () => {
  const fc11Key: EmbeddedCredentialKeyResolver = () => ({ publicKeyJwk: ISSUER_JWK });
  const issuerTrust = { trustChain: trustChain([declaration(ISSUER_ID)]) };

  it('無効化宣言後に発行された内包 SD-JWT VC は 5012 で valid: false', () => {
    const revoked = issueSdJwtVc({ iat: AFTER_REVOKED }, SIGNING_KID);
    const result = verifyPresentation(vpWith(revoked, FC11_NOW), {
      ...holderKey,
      nowSeconds: FC11_NOW,
      credentialKey: fc11Key,
      issuerTrust,
    });
    expect(result.valid).toBe(false);
    expect(result.credentialResults[0]?.errors).toEqual(['5012']);
  });

  it('宣言より前に発行された内包 SD-JWT VC は巻き添えにならず、issuerTrust 未指定なら判定しない', () => {
    const older = issueSdJwtVc({ iat: BEFORE_REVOKED }, SIGNING_KID);
    const withTrust = verifyPresentation(vpWith(older, FC11_NOW), {
      ...holderKey,
      nowSeconds: FC11_NOW,
      credentialKey: fc11Key,
      issuerTrust,
    });
    expect(withTrust.valid).toBe(true);

    const revoked = issueSdJwtVc({ iat: AFTER_REVOKED }, SIGNING_KID);
    const optOut = verifyPresentation(vpWith(revoked, FC11_NOW), {
      ...holderKey,
      nowSeconds: FC11_NOW,
      credentialKey: fc11Key,
    });
    expect(optOut.valid).toBe(true);
  });
});

describe('内包 SD-JWT VC への nowSeconds 中継', () => {
  it('VP の注入時刻で exp を評価する: now < exp なら実時計では失効済みでも valid', () => {
    const entry = sdJwtWith({ iat: PAST, exp: PAST + 100 });
    const result = verifyPresentation(vpWith(entry, PAST), {
      ...holderKey,
      nowSeconds: PAST,
      credentialKey: issuerKeyResolver,
    });
    expect(result.valid).toBe(true);
    expect(result.credentialResults[0]).toMatchObject({ valid: true, isExpired: false });
  });

  it('注入時刻が exp を過ぎていれば 3024（clockSkewSeconds: 0）', () => {
    const entry = sdJwtWith({ iat: PAST, exp: PAST + 100 });
    const result = verifyPresentation(vpWith(entry, PAST + 1000), {
      ...holderKey,
      nowSeconds: PAST + 1000,
      clockSkewSeconds: 0,
      credentialKey: issuerKeyResolver,
    });
    expect(result.valid).toBe(false);
    expect(result.credentialResults[0]?.errors).toEqual(['3024']);
    expect(result.credentialResults[0]?.isExpired).toBe(true);
  });
});

describe('内包 SD-JWT VC への clockSkewSeconds 中継', () => {
  const verifyWithSkew = (exp: number, clockSkewSeconds?: number) =>
    verifyPresentation(vpWith(sdJwtWith({ iat: PAST - 10, exp }), PAST), {
      ...holderKey,
      nowSeconds: PAST,
      ...(clockSkewSeconds === undefined ? {} : { clockSkewSeconds }),
      credentialKey: issuerKeyResolver,
    });

  it('clockSkewSeconds: 0 では exp == now の境界が 3024、exp == now + 1 は valid', () => {
    const atBoundary = verifyWithSkew(PAST, 0);
    expect(atBoundary.valid).toBe(false);
    expect(atBoundary.credentialResults[0]?.errors).toEqual(['3024']);
    expect(verifyWithSkew(PAST + 1, 0).valid).toBe(true);
  });

  it('60 秒前に失効した VC は skew 未指定（既定 120s）なら valid、clockSkewSeconds: 0 なら 3024', () => {
    expect(verifyWithSkew(PAST - 60).valid).toBe(true);
    const strict = verifyWithSkew(PAST - 60, 0);
    expect(strict.valid).toBe(false);
    expect(strict.credentialResults[0]?.errors).toEqual(['3024']);
  });
});
