/**
 * `requireHolderBinding` による内包 JWT-VC の提示者突合の回帰テスト。
 *
 * **修正前の欠陥（PoC）**: `verifyPresentation` は内包 VC の**発行者**署名・時刻・FC-11 しか見て
 * おらず、その VC が提示者（`vp.holder`）のものかを検証していなかった。そのため攻撃者は、
 * 第三者（`did:example:subject`）に正当に発行された公開 VC を自分の VP に詰めるだけで
 * `credentialResults[i].valid === true` かつ `errors` なしの応答を得られた。発行者署名は本物
 * なので検証 API は嘘をついていないが、呼び出し側が「この提示者の VC」と読むと誤る。
 *
 * JWT-VC の提示者突合はオプトインである。
 *
 * - 既定（`requireHolderBinding` 未指定 / `false`）は**従来どおり受理**（後方互換）
 * - `true` のとき `sub !== vp.holder` の VC は `3012` で `valid: false`
 * - `true` のとき `sub` を持たない bearer VC も拒否する
 *
 * 実鍵のみを使う（モック禁止）。VP holder は ES256、VC issuer は ES256K の別鍵にして、
 * 「発行者署名は正当なまま突合だけが落ちる」ことを鍵の分離で示す。
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
/** `sampleVp` が使う提示者 DID。 */
const HOLDER_DID = 'did:example:holder';
/** 第三者（VC の正当な subject）。攻撃者ではないので VC 自体は完全に正当。 */
const OTHER_SUBJECT_DID = 'did:example:subject';

/** 内包 VC の正しい発行者鍵（ES256K）を常に返す DI。 */
const issuerKeyResolver: EmbeddedCredentialKeyResolver = () => ({
  publicKeyJwk: FIXTURES[ISSUER_ALG].jwk,
});

/** VP 署名の検証に必要な最小オプション。 */
const holderKey = { key: { publicKeyJwk: FIXTURES[HOLDER_ALG].jwk }, allowUnbound: true } as const;

/** `credentialSubject` を差し替えた VC を正しい発行者鍵で発行する。 */
function vcFor(
  credentialSubject: Record<string, unknown>,
  alg: typeof ISSUER_ALG | typeof HOLDER_ALG = ISSUER_ALG,
): string {
  const vc = {
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    type: ['VerifiableCredential'],
    issuer: 'did:example:issuer',
    credentialSubject,
    issuanceDate: '2025-01-01T00:00:00Z',
    expirationDate: '2027-01-01T00:00:00Z',
    id: 'urn:uuid:vc-1',
  } as unknown as VerifiableCredential;
  return issueCredential(vc, signerFor(alg), { nowSeconds: NOW });
}

/** 指定の VC 群を内包した JWT-VP を holder 鍵で署名する。 */
function vpWith(entries: readonly string[]): string {
  return issuePresentation(sampleVp({ verifiableCredential: entries }), signerFor(HOLDER_ALG), {
    nowSeconds: NOW,
  });
}

/** 第三者に発行された VC（`sub` は holder ではない）を詰めた VP。 */
function foreignVp(): string {
  return vpWith([vcFor({ id: OTHER_SUBJECT_DID, name: 'Alice' })]);
}

describe('requireHolderBinding による内包 JWT-VC の提示者突合', () => {
  it('第三者の VC を詰めた VP は requireHolderBinding: true で 3012 として弾かれる', () => {
    const result = verifyPresentation(foreignVp(), {
      ...holderKey,
      nowSeconds: NOW,
      credentialKey: issuerKeyResolver,
      requireHolderBinding: true,
    });
    // VP 署名も内包 VC の発行者署名も正当。落ちるのは提示者との突合だけ。
    expect(result.holderDID).toBe(HOLDER_DID);
    expect(result.valid).toBe(false);
    expect(result.credentialResults[0]).toMatchObject({
      valid: false,
      issuerDID: 'did:example:issuer',
      format: 'jwt_vc_json',
    });
    expect(result.credentialResults[0]?.errors).toEqual(['3012']);
    expect(result.errors).toEqual(['3012']);
  });

  it('既定（未指定）では従来どおり第三者の VC でも valid: true になる（後方互換）', () => {
    const result = verifyPresentation(foreignVp(), {
      ...holderKey,
      nowSeconds: NOW,
      credentialKey: issuerKeyResolver,
    });
    expect(result.valid).toBe(true);
    expect(result.errors).toBeUndefined();
  });

  it('requireHolderBinding: false を明示しても既定と同じ（受理）', () => {
    const result = verifyPresentation(foreignVp(), {
      ...holderKey,
      nowSeconds: NOW,
      credentialKey: issuerKeyResolver,
      requireHolderBinding: false,
    });
    expect(result.valid).toBe(true);
  });

  it('sub === vp.holder の VC は requireHolderBinding: true でも valid: true', () => {
    const jwt = vpWith([vcFor({ id: HOLDER_DID, name: 'Alice' })]);
    const result = verifyPresentation(jwt, {
      ...holderKey,
      nowSeconds: NOW,
      credentialKey: issuerKeyResolver,
      requireHolderBinding: true,
    });
    expect(result.valid).toBe(true);
    expect(result.errors).toBeUndefined();
  });

  it('sub を持たない bearer VC は requireHolderBinding: true で拒否される', () => {
    // `credentialSubject.id` が無い VC は `sub` を持たない（`vc/issue.ts`）。設計上正当に存在するが、
    // 突合を要求された文脈では「提示者のものと確認できない」ため受理しない。
    const jwt = vpWith([vcFor({ name: 'Alice' })]);
    const result = verifyPresentation(jwt, {
      ...holderKey,
      nowSeconds: NOW,
      credentialKey: issuerKeyResolver,
      requireHolderBinding: true,
    });
    expect(result.valid).toBe(false);
    expect(result.credentialResults[0]?.errors).toEqual(['3012']);
  });

  it('sub を持たない bearer VC も既定では従来どおり受理される', () => {
    const jwt = vpWith([vcFor({ name: 'Alice' })]);
    const result = verifyPresentation(jwt, {
      ...holderKey,
      nowSeconds: NOW,
      credentialKey: issuerKeyResolver,
    });
    expect(result.valid).toBe(true);
  });

  it('突合は発行者署名の検証後に行う（署名不正な VC は 3012 ではなく 3010 のまま）', () => {
    // holder 鍵（ES256）で「発行」した = 発行者鍵（ES256K）では検証できない。sub も holder と不一致。
    // 未検証 payload の `sub` を先に突き合わせると、署名不正が 3012 に化けて原因が読めなくなる。
    const jwt = vpWith([vcFor({ id: OTHER_SUBJECT_DID }, HOLDER_ALG)]);
    const result = verifyPresentation(jwt, {
      ...holderKey,
      nowSeconds: NOW,
      credentialKey: issuerKeyResolver,
      requireHolderBinding: true,
    });
    expect(result.credentialResults[0]?.errors).toEqual(['3010']);
  });

  it('credentialResults は同順・同数のまま、突合に落ちた VC だけが false になる', () => {
    const own = vcFor({ id: HOLDER_DID });
    const foreign = vcFor({ id: OTHER_SUBJECT_DID });
    const result = verifyPresentation(vpWith([own, foreign, own]), {
      ...holderKey,
      nowSeconds: NOW,
      credentialKey: issuerKeyResolver,
      requireHolderBinding: true,
    });
    expect(result.credentialResults.map((r) => r.valid)).toEqual([true, false, true]);
    expect(result.valid).toBe(false);
  });
});

describe('requireHolderBinding / sub の読み取り（プロトタイプ汚染）', () => {
  it('Object.prototype.requireHolderBinding の汚染で黙って厳格化されない', () => {
    // 継承値を拾うと、突合を要求していない正当な提示が一律 3012 に落ちる（可用性の欠陥）。
    const jwt = foreignVp();
    const result = withPollutedPrototype({ requireHolderBinding: true }, () =>
      verifyPresentation(jwt, {
        ...holderKey,
        nowSeconds: NOW,
        credentialKey: issuerKeyResolver,
      }),
    );
    expect(result.valid).toBe(true);
  });

  it('Object.prototype.sub の汚染で bearer VC が突合を素通りしない', () => {
    // 鎖読みだと `sub` を持たない VC が汚染値を「VC に入っていた sub」として比較され受理される。
    const jwt = vpWith([vcFor({ name: 'Alice' })]);
    const result = withPollutedPrototype({ sub: HOLDER_DID }, () =>
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
});
