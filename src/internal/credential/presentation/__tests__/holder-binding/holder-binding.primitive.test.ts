/**
 * 公開プリミティブ `verifyEmbeddedCredentials` を直接呼ぶ経路の入力読み取り回帰テスト
 * （`credentialKey` / `holderDID`）。
 *
 * `verifyEmbeddedCredentials` は `exports/credential.ts` から公開されており、任意の JS 呼び出し側が
 * 当該キーを**持たない**入力を渡せる。その状態で使用地点が鎖読みだと `Object.prototype` の汚染値が
 * 呼び出し側の入力として採用され fail-open になる。使用地点そのものを own 限定にしていることを固定する。
 *
 * - `credentialKey`: 汚染値が鍵解決に採用され、偽造 VC が `valid: true` になる。ただし関数 DI なので
 *   `class Deps { credentialKey() {} }` のようなプロトタイプメソッド実装が正当であり own 限定には
 *   できない（`Object.prototype` 由来だけを弾く）。その両立も固定する。
 * - `holderDID`: 汚染値が提示者 DID に採用され、被害者の VC の `sub` を据えるだけで第三者の VC が
 *   突合を通る。
 *
 * 独自の委任材料（`delegations`）による突合は削除したため、委任提示は常に `3012` になる。
 */

import { describe, expect, it } from 'bun:test';
import { withPollutedPrototype } from '../../../../__tests__/prototype-pollution.fixtures.js';
import { issueCredential } from '../../../vc/issue.js';
import type { CredentialAlg } from '../../../vc/jws.js';
import type { VerifiableCredential } from '../../../vc/vc.js';
import {
  type EmbeddedCredentialKeyResolver,
  type EmbeddedCredentialVerifyInput,
  verifyEmbeddedCredentials,
} from '../../credential-results.js';
import { FIXTURES, signerFor } from '../presentation.fixtures.js';

const NOW = Math.floor(Date.parse('2026-01-01T00:00:00Z') / 1000);
const ISSUER_ALG = 'ES256K' as const;
/** 内包 VC の subject。提示者とは別 DID なので直接提示の突合は成立しない。 */
const SUBJECT_DID = 'did:example:subject';
/** 提示者（`vp.holder` 相当）。subject と別 DID の提示者はこの VC を提示できてはならない。 */
const HOLDER_DID = 'did:example:holder';

/** 内包 VC の正しい発行者鍵（ES256K）を常に返す DI。発行者署名は常に本物。 */
const issuerKeyResolver: EmbeddedCredentialKeyResolver = () => ({
  publicKeyJwk: FIXTURES[ISSUER_ALG].jwk,
});

/** 指定 subject 向けの JWT-VC を、指定 alg の鍵で署名して発行する。 */
function vcFor(subjectDID: string, alg: CredentialAlg): string {
  const vc = {
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    type: ['VerifiableCredential'],
    issuer: 'did:example:issuer',
    credentialSubject: { id: subjectDID, name: 'Alice' },
    issuanceDate: '2025-01-01T00:00:00Z',
    expirationDate: '2027-01-01T00:00:00Z',
    id: 'urn:uuid:vc-1',
  } as unknown as VerifiableCredential;
  return issueCredential(vc, signerFor(alg), { nowSeconds: NOW });
}

/** 委任元（`SUBJECT_DID`）に正当に発行された JWT-VC。 */
function subjectVc(): string {
  return vcFor(SUBJECT_DID, ISSUER_ALG);
}

/** 攻撃者の鍵（正当な発行者鍵 `ISSUER_ALG` とは別鍵）。偽造 VC の署名に使う。 */
const FORGED_ALG = 'ES256' as const;

/** 攻撃者鍵を「発行者鍵」として返す汚染コールバック（鎖読みならこれが採用される）。 */
const forgedKeyResolver: EmbeddedCredentialKeyResolver = () => ({
  publicKeyJwk: FIXTURES[FORGED_ALG].jwk,
});

/**
 * `credentialKey` キーを**持たない**入力。
 *
 * 突合は本テストの対象外なので `requireHolderBinding: false` にし、鍵解決だけを観測する。
 */
function inputWithoutCredentialKey(): EmbeddedCredentialVerifyInput {
  return {
    issuerTrust: undefined,
    nowSeconds: NOW,
    clockSkewSeconds: undefined,
    holderDID: HOLDER_DID,
    requireHolderBinding: false,
    audience: undefined,
    nonce: undefined,
  } as unknown as EmbeddedCredentialVerifyInput;
}

/** `holderDID` キーを**持たない**入力（突合は要求する）。 */
function inputWithoutHolderDID(): EmbeddedCredentialVerifyInput {
  return {
    credentialKey: issuerKeyResolver,
    issuerTrust: undefined,
    nowSeconds: NOW,
    clockSkewSeconds: undefined,
    requireHolderBinding: true,
    audience: undefined,
    nonce: undefined,
  } as unknown as EmbeddedCredentialVerifyInput;
}

describe('verifyEmbeddedCredentials 直接呼び出しの credentialKey 読み取り', () => {
  it('credentialKey を省略した呼び出しは Object.prototype の汚染値を鍵解決に採らない', () => {
    // 汚染値は攻撃者が選んだ鍵を返す resolver。鎖読みなら攻撃者鍵で偽造 VC の署名が「検証済み」に
    // なり、鍵を渡していない呼び出しが valid: true を返す（fail-open）。
    const forged = vcFor(HOLDER_DID, FORGED_ALG);
    const results = withPollutedPrototype({ credentialKey: forgedKeyResolver }, () =>
      verifyEmbeddedCredentials([forged], inputWithoutCredentialKey()),
    );
    expect(results[0]?.valid).toBe(false);
    expect(results[0]?.errors).toEqual(['3010']);
  });

  it('プロトタイプメソッドで DI した credentialKey は従来どおり採用される', () => {
    // own 限定にすると壊れる正当な形（`class Deps { credentialKey() {} }` 相当）。
    // `Object.prototype` 由来だけを弾く読み方であることを固定する。
    const input = Object.assign(
      Object.create({ credentialKey: issuerKeyResolver }) as object,
      inputWithoutCredentialKey(),
    ) as EmbeddedCredentialVerifyInput;
    const results = verifyEmbeddedCredentials([vcFor(HOLDER_DID, ISSUER_ALG)], input);
    expect(results[0]?.valid).toBe(true);
  });
});

describe('verifyEmbeddedCredentials 直接呼び出しの holderDID 読み取り', () => {
  it('holderDID を省略した呼び出しは Object.prototype の汚染値を提示者 DID に採らない', () => {
    // 汚染値は被害者の VC の `sub`。鎖読みなら `sub === input.holderDID` が成立し、
    // requireHolderBinding: true でも第三者の VC が valid: true になる（fail-open）。
    const results = withPollutedPrototype({ holderDID: SUBJECT_DID }, () =>
      verifyEmbeddedCredentials([subjectVc()], inputWithoutHolderDID()),
    );
    expect(results[0]?.valid).toBe(false);
    expect(results[0]?.errors).toEqual(['3012']);
  });

  it('汚染が無ければ holderDID 省略でも 3012（未解決の提示者は fail-closed）', () => {
    const results = verifyEmbeddedCredentials([subjectVc()], inputWithoutHolderDID());
    expect(results[0]?.valid).toBe(false);
    expect(results[0]?.errors).toEqual(['3012']);
  });
});
