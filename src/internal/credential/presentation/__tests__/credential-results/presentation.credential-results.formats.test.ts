/**
 * 内包 VC 検証のフォーマット別挙動・FC-11 中継・クロックスキュー中継の回帰テスト。
 *
 * `presentation.credential-results.test.ts` が JWT-VC 経路と fail-closed を担当するのに対し、
 * 本ファイルは以下を固定する:
 *
 * - SD-JWT VC 経路（`dc+sd-jwt` / 旧 `vc+sd-jwt` のフォーマット判別、署名検証、`{ verify }` 不可）
 * - `issuerTrust` を内包 VC へ中継して FC-11（5012）が効くこと
 * - `clockSkewSeconds` を内包 VC へ中継すること（中継しないと VP 側の厳格化指定が無視される）
 *
 * 実鍵のみを使う（モック禁止）。VP holder は ES256、内包 VC の issuer は ES256K で別鍵にする。
 */

import { describe, expect, it } from 'bun:test';
import {
  AFTER_REVOKED_ISO,
  BEFORE_REVOKED_ISO,
  declaration,
  NOW as FC11_NOW,
  ISSUER_ID,
  ISSUER_JWK,
  issueJwtVc,
  SIGNING_KID,
  trustChain,
} from '../../../__tests__/issuer-key-revocation/issuer-key-revocation.fixtures.js';
import { createSdJwt } from '../../../sdjwt/sdjwt.js';
import type { SdJwtVcTyp } from '../../../sdjwt/typ.js';
import { issueCredential } from '../../../vc/issue.js';
import type { VerifiableCredential } from '../../../vc/vc.js';
import type { EmbeddedCredentialKeyResolver } from '../../credential-results.js';
import { issuePresentation } from '../../issue.js';
import { verifyPresentation } from '../../presentation.js';
import { FIXTURES, sampleVp, signerFor } from '../presentation.fixtures.js';

const NOW = Math.floor(Date.parse('2026-01-01T00:00:00Z') / 1000);
const HOLDER_ALG = 'ES256' as const;
const ISSUER_ALG = 'ES256K' as const;
const ISSUER_DID = 'did:example:issuer';
const VCT = 'https://example.com/credentials/identity';

/** VP 署名の検証に必要な最小オプション。 */
const holderKey = { key: { publicKeyJwk: FIXTURES[HOLDER_ALG].jwk }, allowUnbound: true } as const;

/** 内包 VC の正しい発行者鍵（ES256K の JWK）を返す DI。 */
const issuerKeyResolver: EmbeddedCredentialKeyResolver = () => ({
  publicKeyJwk: FIXTURES[ISSUER_ALG].jwk,
});

/** 指定の VC 群を内包した JWT-VP を holder 鍵で署名する。 */
function vpWith(entries: readonly string[], nowSeconds = NOW): string {
  return issuePresentation(sampleVp({ verifiableCredential: entries }), signerFor(HOLDER_ALG), {
    nowSeconds,
  });
}

/** 内包用の SD-JWT VC を ES256K 発行者鍵で発行する。 */
function embeddedSdJwt(typ?: SdJwtVcTyp): string {
  const base = {
    vct: VCT,
    disclosureClaims: ['name'],
    claims: { name: 'Alice' },
    salts: { name: 'salt-name' },
    issuer: ISSUER_DID,
    nowSeconds: NOW,
  };
  return createSdJwt(signerFor(ISSUER_ALG), typ === undefined ? base : { ...base, typ });
}

describe('内包 SD-JWT VC の検証', () => {
  it('正しい発行者 JWK で検証が通り、format は dc+sd-jwt になる', () => {
    const result = verifyPresentation(vpWith([embeddedSdJwt()]), {
      ...holderKey,
      nowSeconds: NOW,
      credentialKey: issuerKeyResolver,
    });
    expect(result.valid).toBe(true);
    expect(result.credentialResults[0]).toMatchObject({
      valid: true,
      issuerDID: ISSUER_DID,
      format: 'dc+sd-jwt',
    });
  });

  it('旧 typ で発行された SD-JWT VC は format が vc+sd-jwt になる', () => {
    const result = verifyPresentation(vpWith([embeddedSdJwt('vc+sd-jwt')]), {
      ...holderKey,
      nowSeconds: NOW,
      credentialKey: issuerKeyResolver,
    });
    expect(result.credentialResults[0]).toMatchObject({ valid: true, format: 'vc+sd-jwt' });
  });

  it('{ verify } 形式の鍵は SD-JWT VC では使えず 3010 で fail-closed になる', () => {
    // `verifySdJwt` は issuerKey として PublicKeyJwk を受け付ける。
    const result = verifyPresentation(vpWith([embeddedSdJwt()]), {
      ...holderKey,
      nowSeconds: NOW,
      credentialKey: () => ({ verify: FIXTURES[ISSUER_ALG].verify }),
    });
    expect(result.valid).toBe(false);
    expect(result.credentialResults[0]?.errors).toEqual(['3010']);
  });

  it('別鍵で署名された SD-JWT VC は 3010 で valid: false', () => {
    // holder 鍵（ES256）で発行 = 発行者鍵（ES256K）では検証できない。
    const foreign = createSdJwt(signerFor(HOLDER_ALG), {
      vct: VCT,
      disclosureClaims: [],
      claims: {},
      issuer: ISSUER_DID,
      nowSeconds: NOW,
    });
    const result = verifyPresentation(vpWith([foreign]), {
      ...holderKey,
      nowSeconds: NOW,
      credentialKey: issuerKeyResolver,
    });
    expect(result.valid).toBe(false);
    expect(result.credentialResults[0]?.errors).toEqual(['3010']);
  });

  it('デコードできない SD-JWT（~ を含むだけの文字列）は 3010 で valid: false', () => {
    const result = verifyPresentation(vpWith(['not-a-sd-jwt~']), {
      ...holderKey,
      nowSeconds: NOW,
      credentialKey: issuerKeyResolver,
    });
    expect(result.credentialResults[0]).toMatchObject({ valid: false, issuerDID: '' });
  });
});

describe('issuerTrust の内包 VC への中継（FC-11）', () => {
  /** FC-11 フィクスチャの発行者鍵で内包 JWT-VC を検証する DI。 */
  const fc11KeyResolver: EmbeddedCredentialKeyResolver = () => ({ publicKeyJwk: ISSUER_JWK });

  it('無効化宣言後に発行された内包 VC は 5012 で valid: false になる', () => {
    const revoked = issueJwtVc(AFTER_REVOKED_ISO, SIGNING_KID);
    const result = verifyPresentation(vpWith([revoked], FC11_NOW), {
      ...holderKey,
      nowSeconds: FC11_NOW,
      credentialKey: fc11KeyResolver,
      issuerTrust: { trustChain: trustChain([declaration(ISSUER_ID)]) },
    });
    expect(result.valid).toBe(false);
    expect(result.credentialResults[0]?.errors).toEqual(['5012']);
    expect(result.errors).toEqual(['5012']);
  });

  it('宣言より前に発行された内包 VC は巻き添えにならない（valid: true）', () => {
    const older = issueJwtVc(BEFORE_REVOKED_ISO, SIGNING_KID);
    const result = verifyPresentation(vpWith([older], FC11_NOW), {
      ...holderKey,
      nowSeconds: FC11_NOW,
      credentialKey: fc11KeyResolver,
      issuerTrust: { trustChain: trustChain([declaration(ISSUER_ID)]) },
    });
    expect(result.valid).toBe(true);
  });

  it('issuerTrust を渡さなければ FC-11 は判定しない（opt-in）', () => {
    const revoked = issueJwtVc(AFTER_REVOKED_ISO, SIGNING_KID);
    const result = verifyPresentation(vpWith([revoked], FC11_NOW), {
      ...holderKey,
      nowSeconds: FC11_NOW,
      credentialKey: fc11KeyResolver,
    });
    expect(result.valid).toBe(true);
  });
});

describe('clockSkewSeconds の内包 VC への中継', () => {
  /** `NOW` の 60 秒前に失効した内包 JWT-VC。 */
  function expiredVc(): string {
    const vc: VerifiableCredential = {
      '@context': ['https://www.w3.org/ns/credentials/v2'],
      type: ['VerifiableCredential'],
      issuer: ISSUER_DID,
      credentialSubject: { id: 'did:example:subject' },
      issuanceDate: '2025-01-01T00:00:00Z',
      expirationDate: new Date((NOW - 60) * 1000).toISOString(),
      id: 'urn:uuid:vc-skew',
    };
    return issueCredential(vc, signerFor(ISSUER_ALG), { nowSeconds: NOW - 3600 });
  }

  it('clockSkewSeconds: 0 を指定すると 60 秒前に失効した内包 VC が 3024 で弾かれる', () => {
    // 中継されないと内包 VC は VC 既定の 120s で評価され、この VC が valid: true で通ってしまう。
    const result = verifyPresentation(vpWith([expiredVc()]), {
      ...holderKey,
      nowSeconds: NOW,
      clockSkewSeconds: 0,
      credentialKey: issuerKeyResolver,
    });
    expect(result.valid).toBe(false);
    expect(result.credentialResults[0]).toMatchObject({ valid: false, isExpired: true });
    expect(result.credentialResults[0]?.errors).toEqual(['3024']);
  });

  it('clockSkewSeconds 未指定なら VC 既定（120s）の許容で通る（既定挙動は不変）', () => {
    const result = verifyPresentation(vpWith([expiredVc()]), {
      ...holderKey,
      nowSeconds: NOW,
      credentialKey: issuerKeyResolver,
    });
    expect(result.valid).toBe(true);
  });
});
