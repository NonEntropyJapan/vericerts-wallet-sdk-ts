/**
 * `verifyPresentation` への Trusted Issuer List() 配線の回帰テスト。
 *
 * 修正前は `credentialResults[].isTrustedIssuer` が常に `null`（未実行）で、`TrustedIssuerListStore` /
 * `isTrustedIssuer` は提示検証パイプラインから呼ばれていなかった。`trustedIssuerList` を DI した場合に内包 VC の `issuerDID` が実際に
 * 照合され、結果へ反映されることを確認する。
 */

import { describe, expect, it } from 'bun:test';
import type { TrustedIssuerList } from '../../../trusted-issuer/types.js';
import { createSdJwt } from '../../sdjwt/sdjwt.js';
import { issueCredential } from '../../vc/issue.js';
import type { VerifiableCredential } from '../../vc/vc.js';
import type { EmbeddedCredentialKeyResolver } from '../credential-results.js';
import { issuePresentation } from '../issue.js';
import { verifyPresentation } from '../presentation.js';
import { VC_V2_CONTEXT } from '../vp.js';
import { FIXTURES, sampleVp, signerFor } from './presentation.fixtures.js';

const NOW = Math.floor(Date.parse('2026-01-01T00:00:00Z') / 1000);
const HOLDER_ALG = 'ES256' as const;
const ISSUER_ALG = 'ES256K' as const;
const ISSUER_DID = 'did:example:issuer';
const ISSUER_KEY = { publicKeyJwk: FIXTURES[ISSUER_ALG].jwk } as const;
const issuerKeyResolver: EmbeddedCredentialKeyResolver = () => ISSUER_KEY;
const holderKey = { key: { publicKeyJwk: FIXTURES[HOLDER_ALG].jwk }, allowUnbound: true } as const;

function sampleVc(type: string[] = ['VerifiableCredential']): VerifiableCredential {
  return {
    '@context': [VC_V2_CONTEXT],
    type,
    issuer: ISSUER_DID,
    credentialSubject: { id: 'did:example:holder' },
    issuanceDate: '2025-01-01T00:00:00Z',
    expirationDate: '2030-01-01T00:00:00Z',
    id: 'urn:uuid:vc-til-1',
  } as unknown as VerifiableCredential;
}

/** 発行者鍵（ES256K）で署名した内包用 JWT-VC。 */
function embeddedVc(type?: string[]): string {
  return issueCredential(sampleVc(type), signerFor(ISSUER_ALG), { nowSeconds: NOW });
}

/** 発行者鍵（ES256K）で署名した内包用 SD-JWT VC（`vct` 指定）。 */
function embeddedSdJwt(vct: string): string {
  return createSdJwt(signerFor(ISSUER_ALG), {
    vct,
    disclosureClaims: ['name'],
    claims: { name: 'Alice' },
    salts: { name: 'salt-name' },
    issuer: ISSUER_DID,
    nowSeconds: NOW,
  });
}

/** 指定の VC を内包した JWT-VP を holder 鍵で署名する。 */
function vpWith(entries: readonly string[]): string {
  return issuePresentation(sampleVp({ verifiableCredential: entries }), signerFor(HOLDER_ALG), {
    nowSeconds: NOW,
  });
}

function trustedIssuerListWith(
  issuerDids: readonly string[],
  extra: { credentialTypes?: string[]; validUntil?: string } = {},
): TrustedIssuerList {
  return {
    id: 'til-1',
    type: 'TrustedIssuerList',
    version: 'TSLv1',
    listOperator: 'did:example:operator',
    listName: 'Test TIL',
    issuedAt: '2025-01-01T00:00:00Z',
    trustedIssuers: issuerDids.map((id) => ({ id, name: id, ...extra })),
  };
}

describe('verifyPresentation の Trusted Issuer List 照合', () => {
  it('trustedIssuerList 未指定なら従来どおり isTrustedIssuer: null（未実行）', () => {
    const jwt = vpWith([embeddedVc()]);
    const result = verifyPresentation(jwt, {
      ...holderKey,
      nowSeconds: NOW,
      credentialKey: issuerKeyResolver,
    });
    expect(result.valid).toBe(true);
    expect(result.credentialResults[0]?.isTrustedIssuer).toBeNull();
  });

  it('issuerDID がリストの信頼済みエントリに一致すれば isTrustedIssuer: true', () => {
    const jwt = vpWith([embeddedVc()]);
    const result = verifyPresentation(jwt, {
      ...holderKey,
      nowSeconds: NOW,
      credentialKey: issuerKeyResolver,
      trustedIssuerList: trustedIssuerListWith([ISSUER_DID]),
    });
    expect(result.valid).toBe(true);
    expect(result.credentialResults[0]?.isTrustedIssuer).toBe(true);
  });

  it('issuerDID がリストに無ければ isTrustedIssuer: false（VC 自体は有効なままでよい）', () => {
    const jwt = vpWith([embeddedVc()]);
    const result = verifyPresentation(jwt, {
      ...holderKey,
      nowSeconds: NOW,
      credentialKey: issuerKeyResolver,
      trustedIssuerList: trustedIssuerListWith(['did:example:someone-else']),
    });
    expect(result.valid).toBe(true);
    expect(result.credentialResults[0]?.isTrustedIssuer).toBe(false);
  });

  it('内包 VC の署名検証に失敗しても issuerDID が取れていれば TIL 照合は行われる', () => {
    // credentialKey を渡さない = 発行者鍵を解決できず fail-closed（3010）。
    const jwt = vpWith([embeddedVc()]);
    const result = verifyPresentation(jwt, {
      ...holderKey,
      nowSeconds: NOW,
      trustedIssuerList: trustedIssuerListWith([ISSUER_DID]),
    });
    expect(result.valid).toBe(false);
    expect(result.credentialResults[0]?.errors).toEqual(['3010']);
    expect(result.credentialResults[0]?.issuerDID).toBe(ISSUER_DID);
    expect(result.credentialResults[0]?.isTrustedIssuer).toBe(true);
  });
});

describe('verifyPresentation の TIL 照合は VC 種別・基準時刻を渡す', () => {
  const verifyWith = (entry: string, trustedIssuerList: TrustedIssuerList) =>
    verifyPresentation(vpWith([entry]), {
      ...holderKey,
      nowSeconds: NOW,
      credentialKey: issuerKeyResolver,
      trustedIssuerList,
    }).credentialResults[0];
  const university = trustedIssuerListWith([ISSUER_DID], { credentialTypes: ['UniversityDegree'] });

  it('JWT-VC: 種別制限された発行者が権限のない種別を発行しても信頼済みにならない', () => {
    const result = verifyWith(
      embeddedVc(['VerifiableCredential', 'BankAccountCredential']),
      university,
    );
    expect(result?.valid).toBe(true);
    expect(result?.isTrustedIssuer).toBe(false);
  });

  it('JWT-VC: vc.type のいずれかがエントリの credentialTypes に含まれれば信頼済み', () => {
    const result = verifyWith(embeddedVc(['VerifiableCredential', 'UniversityDegree']), university);
    expect(result?.isTrustedIssuer).toBe(true);
  });

  it('JWT-VC: 種別制限の無いエントリは全種別で信頼済み（従来どおり）', () => {
    const result = verifyWith(
      embeddedVc(['VerifiableCredential', 'BankAccountCredential']),
      trustedIssuerListWith([ISSUER_DID]),
    );
    expect(result?.isTrustedIssuer).toBe(true);
  });

  it('SD-JWT VC: vct が credentialTypes に含まれなければ false、含まれれば true', () => {
    expect(verifyWith(embeddedSdJwt('BankAccountCredential'), university)?.isTrustedIssuer).toBe(
      false,
    );
    const result = verifyWith(embeddedSdJwt('UniversityDegree'), university);
    expect(result?.valid).toBe(true);
    expect(result?.isTrustedIssuer).toBe(true);
  });

  it('署名検証に失敗した VC でも種別制限は評価される（種別が取れる場合）', () => {
    const result = verifyPresentation(
      vpWith([embeddedVc(['VerifiableCredential', 'BankAccountCredential'])]),
      {
        ...holderKey,
        nowSeconds: NOW,
        trustedIssuerList: university,
      },
    ).credentialResults[0];
    expect(result?.errors).toEqual(['3010']);
    expect(result?.isTrustedIssuer).toBe(false);
  });

  it('validUntil は壁時計ではなく検証の nowSeconds で評価する', () => {
    // 壁時計では失効済みでも、検証基準時刻（2026-01-01）では有効期間内。
    const list = trustedIssuerListWith([ISSUER_DID], { validUntil: '2026-06-01T00:00:00Z' });
    expect(verifyWith(embeddedVc(), list)?.isTrustedIssuer).toBe(true);
    const expired = trustedIssuerListWith([ISSUER_DID], { validUntil: '2025-12-31T00:00:00Z' });
    expect(verifyWith(embeddedVc(), expired)?.isTrustedIssuer).toBe(false);
  });
});
