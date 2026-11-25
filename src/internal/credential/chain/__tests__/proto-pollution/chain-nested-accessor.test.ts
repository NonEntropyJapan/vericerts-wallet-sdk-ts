/**
 * `buildDerivedCredential` の**入れ子** own アクセサ再評価耐性テスト。
 *
 * `child` のスナップショットはスプレッド 1 段だけだったため、入れ子のオブジェクトは**参照ごと
 * コピー**され、その中の own アクセサが生き残っていた。Art.9 走査器
 * （`special-category.ts`）は各階層の**キー名**でしか判定しないので、入れ子アクセサが
 * **キー集合ごと違うオブジェクト**（1 回目は無害・2 回目に Art.9 属性）を返すと、10607 を
 * 素通りした値が派生 VC の `credentialSubject` に載り、そのまま署名・保存・転送され得た。
 *
 * `internal/prototype-safety/deep-snapshot.ts` で入れ子まで畳んでいることを固定する（深い畳みを外すと落ちる）。
 * 発行系（`IssuerModule.issueVC`）と DID Log 経路の同型テストは
 * `issuer/__tests__/module/issue-vc-nested-accessor.test.ts` /
 * `identity/webvh/__tests__/lifecycle/lifecycle.nested-accessor.test.ts`。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../../../errors.js';
import type { VerifiableCredential } from '../../../vc/vc.js';
import { buildDerivedCredential } from '../../build.js';
import type { DerivedCredentialInput } from '../../types.js';

const SPECIAL_CATEGORY = new VericertsError(ErrorCodes.GDPR_SPECIAL_CATEGORY_ISSUANCE);

const V2_CONTEXT = 'https://www.w3.org/ns/credentials/v2';
const PARENT_ID = 'urn:uuid:parent-1';
const CHILD_ID = 'urn:uuid:child-1';
const ISSUER_DID = 'did:example:issuer';
const SUBJECT_DID = 'did:example:subject';

/** 1 回目の読み取りで返る無害な値（Art.9 属性名を持たない）。 */
const CLEAN_META = { region: 'jp' } as const;
/** 2 回目以降で返る Art.9 属性入りの値。 */
const TOXIC_META = { diagnosis: 'HIV+' } as const;

/** 最小の親 VC。 */
function parentVc(): VerifiableCredential {
  return {
    '@context': [V2_CONTEXT],
    type: ['VerifiableCredential'],
    issuer: ISSUER_DID,
    credentialSubject: { id: SUBJECT_DID },
    issuanceDate: '2026-01-01T00:00:00Z',
    id: PARENT_ID,
  };
}

/**
 * `credentialSubject.profile` に読み取り回数依存の own アクセサを持つ子 VC。
 *
 * アクセサは**入れ子（深さ 1）**に置く。トップレベルの `credentialSubject` に置くと 1 段の
 * スプレッドで畳まれてしまい、ネストした値の検査（深さ 1 以上）から外れる。
 */
function childWithNestedAccessor(values: readonly unknown[]): {
  readonly child: DerivedCredentialInput;
  reads: () => number;
} {
  let readCount = 0;
  const credentialSubject: Record<string, unknown> = { id: SUBJECT_DID };
  Object.defineProperty(credentialSubject, 'profile', {
    configurable: true,
    enumerable: true,
    get(): unknown {
      const value = values[Math.min(readCount, values.length - 1)];
      readCount += 1;
      return value;
    },
  });
  const child = {
    '@context': [V2_CONTEXT],
    type: ['VerifiableCredential'],
    issuer: ISSUER_DID,
    credentialSubject,
    issuanceDate: '2026-01-01T00:00:00Z',
    id: CHILD_ID,
  } as unknown as DerivedCredentialInput;
  return { child, reads: () => readCount };
}

describe('buildDerivedCredential の入れ子 own アクセサ再評価耐性', () => {
  it('2 回目に Art.9 属性へすり替わる入れ子アクセサでも派生 VC に載らない', () => {
    const { child } = childWithNestedAccessor([CLEAN_META, TOXIC_META]);

    const derived = buildDerivedCredential(parentVc(), child);

    expect(JSON.stringify(derived)).not.toContain('diagnosis');
    expect(JSON.stringify(derived)).toContain('"region":"jp"');
  });

  it('入れ子アクセサは 1 度しか評価されない（走査と戻り値組み立てで読み直さない）', () => {
    const { child, reads } = childWithNestedAccessor([CLEAN_META, TOXIC_META]);

    const derived = buildDerivedCredential(parentVc(), child);
    // 戻り値の直列化でも再評価されないこと（畳んでいれば通常のデータプロパティ）。
    JSON.stringify(derived);

    expect(reads()).toBe(1);
  });

  it('1 回目の読み取りが Art.9 属性を返す入れ子アクセサは 10607 で拒否される', () => {
    const { child } = childWithNestedAccessor([TOXIC_META, CLEAN_META]);

    expect(() => buildDerivedCredential(parentVc(), child)).toThrow(SPECIAL_CATEGORY);
  });

  it('対照: 入れ子アクセサを持たない子 VC は従来どおり構築できる', () => {
    const child = {
      '@context': [V2_CONTEXT],
      type: ['VerifiableCredential'],
      issuer: ISSUER_DID,
      credentialSubject: { id: SUBJECT_DID, profile: CLEAN_META },
      issuanceDate: '2026-01-01T00:00:00Z',
      id: CHILD_ID,
    } as unknown as DerivedCredentialInput;

    const derived = buildDerivedCredential(parentVc(), child);

    expect(derived.derivedFrom).toBe(PARENT_ID);
    expect((derived.credentialSubject as Record<string, unknown>).profile).toEqual(CLEAN_META);
  });

  it('対照: 入れ子の非列挙 own プロパティの Art.9 属性は従来どおり載らない（走査範囲 == 反映範囲）', () => {
    const credentialSubject: Record<string, unknown> = { id: SUBJECT_DID };
    const profile: Record<string, unknown> = { region: 'jp' };
    Object.defineProperty(profile, 'diagnosis', {
      configurable: true,
      enumerable: false,
      value: 'HIV+',
      writable: true,
    });
    credentialSubject.profile = profile;
    const child = {
      '@context': [V2_CONTEXT],
      type: ['VerifiableCredential'],
      issuer: ISSUER_DID,
      credentialSubject,
      issuanceDate: '2026-01-01T00:00:00Z',
      id: CHILD_ID,
    } as unknown as DerivedCredentialInput;

    // 深さ 1 以上の**非列挙**プロパティは走査器（`Object.getOwnPropertyNames`）から見えるため
    // 10607 で拒否される。列挙可能へ格上げして派生 VC に載せる、という退行が起きないことを固定する。
    expect(() => buildDerivedCredential(parentVc(), child)).toThrow(SPECIAL_CATEGORY);
  });
});
