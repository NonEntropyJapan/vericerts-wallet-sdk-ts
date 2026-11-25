/**
 * ODRL 制限抽出の null プロトタイプ耐性テスト。
 *
 * `parseVerifiableCredential` は `parseJsonWithoutPrototype` を通るため、VC 本文由来のオブジェクトは
 * `Object.prototype` を継承しない（＝`toString` / `valueOf` を持たない）。`extractRestrictions` が
 * `operator` / `rightOperand` を検証せずに暗黙の `ToPrimitive`（`String()` / `Array#join`）へ渡すと
 * `TypeError: No default value` になり、公開 API `checkTermsOfUse` が生の例外を漏らしていた。
 *
 * `extractRestrictions` はマッチ判定より前に**無条件で**呼ばれるため、この例外は ToU 評価そのものを
 * 落とす。**素のオブジェクトリテラルでは再現しない**ため、必ずパース境界（JSON 文字列）を通す。
 */

import { describe, expect, it } from 'bun:test';
import { parseVerifiableCredential } from '../../../presentation/vc-assert.js';
import { checkTermsOfUse } from '../../terms-of-use.js';

const CONTEXT = ['https://www.w3.org/ns/credentials/v2'];

/** 任意の termsOfUse エントリを持つ VC を JSON 経由でパースする。 */
function vcWithTermsOfUse(entry: unknown) {
  return parseVerifiableCredential(
    JSON.stringify({
      '@context': CONTEXT,
      type: ['VerifiableCredential'],
      issuer: 'did:example:issuer',
      credentialSubject: { id: 'did:example:holder' },
      issuanceDate: '2026-01-01T00:00:00Z',
      termsOfUse: [entry],
    }),
  );
}

/** `prohibition` に 1 件の制約を持つ VC を JSON 経由でパースする。 */
function vcWithProhibitionConstraint(constraint: unknown) {
  return vcWithTermsOfUse({
    type: 'OdrlPolicy',
    prohibition: [{ action: 'use', constraint: [constraint] }],
  });
}

const CONTEXT_KYC = { verifierId: 'did:example:verifier', purpose: 'kyc' } as const;

describe('extractRestrictions — 型未検証のオペランドで例外を投げない', () => {
  it('operator がオブジェクトでも TypeError にならず制限を代替表記で残す', async () => {
    const vc = vcWithProhibitionConstraint({
      leftOperand: 'purpose',
      operator: { a: 1 },
      rightOperand: 'kyc',
    });

    const result = await checkTermsOfUse(vc, CONTEXT_KYC);

    // 制限は黙って消さない（fail-open を作らない）。表記だけ安全側へ倒す。
    expect(result.restrictions).toHaveLength(1);
    expect(result.restrictions[0]?.kind).toBe('purpose');
    expect(result.restrictions[0]?.description).toBe('prohibition: purpose <invalid value> kyc');
    // 構造不正な制約は合致とみなさないため、fail-open 既定では違反にならない。
    expect(result.compliant).toBe(true);
  });

  it('rightOperand がオブジェクトでも TypeError にならない', async () => {
    const vc = vcWithProhibitionConstraint({
      leftOperand: 'purpose',
      operator: 'eq',
      rightOperand: { a: 1 },
    });

    const result = await checkTermsOfUse(vc, CONTEXT_KYC);

    expect(result.restrictions[0]?.description).toBe('prohibition: purpose eq <invalid value>');
  });

  it('rightOperand 配列に非文字列要素が混ざっても TypeError にならない', async () => {
    const vc = vcWithProhibitionConstraint({
      leftOperand: 'purpose',
      operator: 'isAnyOf',
      rightOperand: ['kyc', { a: 1 }],
    });

    const result = await checkTermsOfUse(vc, CONTEXT_KYC);

    expect(result.restrictions[0]?.description).toBe(
      'prohibition: purpose isAnyOf kyc, <invalid value>',
    );
  });

  it('妥当な制約の表記は従来どおり（回帰なし）', async () => {
    const vc = vcWithProhibitionConstraint({
      leftOperand: 'purpose',
      operator: 'eq',
      rightOperand: 'kyc',
    });

    const result = await checkTermsOfUse(vc, CONTEXT_KYC);

    expect(result.restrictions[0]?.description).toBe('prohibition: purpose eq kyc');
    expect(result.compliant).toBe(false);
  });
});

describe('describeOperand — 安全に文字列化できる値は表示情報を落とさない', () => {
  it('rightOperand が数値でも代替表記へ潰さない', async () => {
    const vc = vcWithProhibitionConstraint({
      leftOperand: 'count',
      operator: 'lteq',
      rightOperand: 5,
    });

    const result = await checkTermsOfUse(vc, CONTEXT_KYC);

    expect(result.restrictions[0]?.description).toBe('prohibition: count lteq 5');
  });

  it('rightOperand が真偽値・null でも代替表記へ潰さない', async () => {
    const vcBool = vcWithProhibitionConstraint({
      leftOperand: 'redistribute',
      operator: 'eq',
      rightOperand: false,
    });
    const vcNull = vcWithProhibitionConstraint({
      leftOperand: 'purpose',
      operator: 'eq',
      rightOperand: null,
    });

    expect((await checkTermsOfUse(vcBool, CONTEXT_KYC)).restrictions[0]?.description).toBe(
      'prohibition: redistribute eq false',
    );
    expect((await checkTermsOfUse(vcNull, CONTEXT_KYC)).restrictions[0]?.description).toBe(
      'prohibition: purpose eq null',
    );
  });

  it('rightOperand 配列の数値要素も潰さない', async () => {
    const vc = vcWithProhibitionConstraint({
      leftOperand: 'count',
      operator: 'isAnyOf',
      rightOperand: [1, 'kyc'],
    });

    const result = await checkTermsOfUse(vc, CONTEXT_KYC);

    expect(result.restrictions[0]?.description).toBe('prohibition: count isAnyOf 1, kyc');
  });

  it('operator が数値でも代替表記へ潰さない', async () => {
    const vc = vcWithProhibitionConstraint({
      leftOperand: 'purpose',
      operator: 7,
      rightOperand: 'kyc',
    });

    const result = await checkTermsOfUse(vc, CONTEXT_KYC);

    expect(result.restrictions[0]?.description).toBe('prohibition: purpose 7 kyc');
  });
});

/**
 * `termsOfUse[].id` は型宣言こそ `string | undefined` だが、`collectEntries` の `isRecord` しか
 * 通っていないため実体は VC 本文の任意の値。`null` プロトタイプのオブジェクトをテンプレート
 * リテラルへ渡すと `TypeError: No default value` になり `checkTermsOfUse` が結果を返さず落ちる。
 *
 * 生成サイトは `odrl.ts` の `ruleId` と `policy-eval.ts` の allowlist 違反の 2 箇所。permission 側は
 * `uid` を与えて `ruleId` を短絡させ、allowlist 違反サイトだけを踏ませる。
 */
describe('ruleId / allowlist 違反 — entry.id が非文字列でも例外を投げない', () => {
  it('prohibition 合致経路: 既定表記の ruleId で違反を返す', async () => {
    const vc = vcWithTermsOfUse({
      type: 'OdrlPolicy',
      id: { evil: 1 },
      prohibition: [
        {
          action: 'use',
          constraint: [{ leftOperand: 'purpose', operator: 'eq', rightOperand: 'kyc' }],
        },
      ],
    });

    const result = await checkTermsOfUse(vc, CONTEXT_KYC);

    expect(result.compliant).toBe(false);
    expect(result.violations[0]?.ruleId).toBe('tou#prohibition[0]');
  });

  it('permission allowlist 経路: 既定表記の ruleId で違反を返す', async () => {
    const vc = vcWithTermsOfUse({
      type: 'OdrlPolicy',
      id: { evil: 1 },
      permission: [
        {
          uid: 'urn:rule:permission-1',
          action: 'use',
          constraint: [{ leftOperand: 'purpose', operator: 'eq', rightOperand: 'marketing' }],
        },
      ],
    });

    const result = await checkTermsOfUse(vc, CONTEXT_KYC);

    expect(result.compliant).toBe(false);
    expect(result.violations[0]?.ruleId).toBe('tou#permission');
  });
});
