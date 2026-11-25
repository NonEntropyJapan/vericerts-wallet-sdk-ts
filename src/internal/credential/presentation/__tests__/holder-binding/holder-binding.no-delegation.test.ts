/**
 * 委任提示（`sub !== vp.holder`）は拒否される回帰テスト。
 *
 * 独自の委任材料 `delegations`（旧 SubjectBinding / DelegationGrant 由来のアダプタ出力）による
 * holder 突合は削除した。`requireHolderBinding: true` で受理される提示は直接提示
 * （`sub === vp.holder`）だけで、`delegations` を（型を迂回して）渡しても、`Object.prototype` を
 * 汚染しても、`sub !== vp.holder` の VC は `3012` のままである。
 *
 * 実鍵のみを使う（モック禁止）。VP holder は ES256、VC issuer は ES256K の別鍵にして、
 * 「発行者署名は正当なまま突合だけが判定を分ける」ことを鍵の分離で示す。
 */

import { describe, expect, it } from 'bun:test';
import { withPollutedPrototype } from '../../../../__tests__/prototype-pollution.fixtures.js';
import { issueCredential } from '../../../vc/issue.js';
import type { VerifiableCredential } from '../../../vc/vc.js';
import type { EmbeddedCredentialKeyResolver } from '../../credential-results.js';
import { issuePresentation } from '../../issue.js';
import { verifyPresentation } from '../../presentation.js';
import { FIXTURES, sampleVp, signerFor } from '../presentation.fixtures.js';

const NOW = Math.floor(Date.parse('2026-01-01T00:00:00Z') / 1000);
const HOLDER_ALG = 'ES256' as const;
const ISSUER_ALG = 'ES256K' as const;
/** 内包 VC の subject。`sampleVp` の holder（`did:example:holder`）とは別 DID。 */
const SUBJECT_DID = 'did:example:subject';
const HOLDER_DID = 'did:example:holder';

/** 内包 VC の正しい発行者鍵（ES256K）を常に返す DI。 */
const issuerKeyResolver: EmbeddedCredentialKeyResolver = () => ({
  publicKeyJwk: FIXTURES[ISSUER_ALG].jwk,
});

/** VP 署名の検証に必要な最小オプション。 */
const holderKey = { key: { publicKeyJwk: FIXTURES[HOLDER_ALG].jwk }, allowUnbound: true } as const;

/** 別 subject に正当に発行された VC。発行者署名は常に本物。 */
function subjectVc(): string {
  const vc = {
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    type: ['VerifiableCredential'],
    issuer: 'did:example:issuer',
    credentialSubject: { id: SUBJECT_DID, name: 'Alice' },
    issuanceDate: '2025-01-01T00:00:00Z',
    expirationDate: '2027-01-01T00:00:00Z',
    id: 'urn:uuid:vc-1',
  } as unknown as VerifiableCredential;
  return issueCredential(vc, signerFor(ISSUER_ALG), { nowSeconds: NOW });
}

/** 提示者（`HOLDER_DID`）が別 subject の VC を詰めて提示する VP。 */
function delegatedVp(): string {
  return issuePresentation(
    sampleVp({ verifiableCredential: [subjectVc()] }),
    signerFor(HOLDER_ALG),
    { nowSeconds: NOW },
  );
}

const FORGED_DELEGATION = { subjectDID: SUBJECT_DID, holderDID: HOLDER_DID, scope: ['present'] };

describe('委任提示は受理されない', () => {
  it('requireHolderBinding: true で sub !== vp.holder の VC は 3012', () => {
    const result = verifyPresentation(delegatedVp(), {
      ...holderKey,
      nowSeconds: NOW,
      credentialKey: issuerKeyResolver,
      requireHolderBinding: true,
    });
    expect(result.valid).toBe(false);
    expect(result.credentialResults[0]?.errors).toEqual(['3012']);
  });

  it('削除済みの delegations を JS 呼び出しで渡しても無視され 3012', () => {
    const options = {
      ...holderKey,
      nowSeconds: NOW,
      credentialKey: issuerKeyResolver,
      requireHolderBinding: true,
      delegations: [FORGED_DELEGATION],
    } as unknown as Parameters<typeof verifyPresentation>[1];
    const result = verifyPresentation(delegatedVp(), options);
    expect(result.valid).toBe(false);
    expect(result.credentialResults[0]?.errors).toEqual(['3012']);
  });

  it('Object.prototype.delegations の汚染でも 3012', () => {
    const jwt = delegatedVp();
    const result = withPollutedPrototype({ delegations: [FORGED_DELEGATION] }, () =>
      verifyPresentation(jwt, {
        ...holderKey,
        nowSeconds: NOW,
        credentialKey: issuerKeyResolver,
        requireHolderBinding: true,
      }),
    );
    expect(result.valid).toBe(false);
    expect(result.credentialResults[0]?.errors).toEqual(['3012']);
  });

  it('requireHolderBinding: false（既定）なら従来どおり受理（後方互換）', () => {
    const result = verifyPresentation(delegatedVp(), {
      ...holderKey,
      nowSeconds: NOW,
      credentialKey: issuerKeyResolver,
    });
    expect(result.valid).toBe(true);
  });
});
