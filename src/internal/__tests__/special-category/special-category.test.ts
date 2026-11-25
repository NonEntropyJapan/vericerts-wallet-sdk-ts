/**
 * GDPR Art.9 特別カテゴリ属性ガード（`10601`）のテスト。
 *
 * - 語彙表の各カテゴリ（人種 / 政治的信条 / 宗教 / 労働組合 / 健康 / 性的指向 / 遺伝子・生体 /
 *   国民識別番号 / PID 生データ）を代表属性で検知する
 * - 命名揺れ（snake_case / camelCase / kebab-case / 大文字）を正規化して検知する
 * - JSON-LD の圧縮 IRI（`pid:birth_date`）も展開済み IRI（`https://schema.org/birthDate` /
 *   `https://example.org/ns#religion`）も検知し、IRI 形式の無害なキーは検知しない
 * - 入れ子オブジェクト・配列の内部まで走査する
 * - 循環参照を含む値でも停止する
 * - プロトタイプ鎖の汚染値は拾わない（誤検知しない）
 * - W3C DID Core の正規な語彙だけの DID Document は検知しない（誤検知しない）
 * - 一致時に `assertNoSpecialCategoryOnChain` が 10601 を投げ、例外に属性名を載せない
 * - 一致時に `assertNoSpecialCategoryInIssuedContent` が 10607 を投げ、例外に属性名を載せない
 *
 * PID 生データを Issue 時に拒否し続けること・`10601` と `10607` の禁止語彙が同一であることの
 * 固定は、`special-category-pid-issuance.test.ts` が担う。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../errors.js';
import {
  assertNoSpecialCategoryInIssuedContent,
  assertNoSpecialCategoryOnChain,
  findSpecialCategoryAttributes,
  normalizeAttributeName,
  SPECIAL_CATEGORY_ATTRIBUTES,
} from '../../special-category.js';

const SPECIAL_CATEGORY = new VericertsError(ErrorCodes.GDPR_SPECIAL_CATEGORY_ON_CHAIN);
const SPECIAL_CATEGORY_ISSUANCE = new VericertsError(ErrorCodes.GDPR_SPECIAL_CATEGORY_ISSUANCE);

/** 特別カテゴリ属性ガードが拒否する代表的な属性名。 */
const REPRESENTATIVE_ATTRIBUTES: readonly [string, string][] = [
  ['race', 'race'],
  ['ethnicity', 'ethnicity'],
  ['political_opinion', 'politicalopinion'],
  ['religion', 'religion'],
  ['trade_union_membership', 'tradeunionmembership'],
  ['health', 'health'],
  ['sexual_orientation', 'sexualorientation'],
  ['genetic_data', 'geneticdata'],
  ['biometric_data', 'biometricdata'],
  ['national_id', 'nationalid'],
  ['family_name', 'familyname'],
  ['given_name', 'givenname'],
  ['birth_date', 'birthdate'],
  ['birth_place', 'birthplace'],
];

describe('normalizeAttributeName', () => {
  it('小文字化し英数字以外を落とす', () => {
    expect(normalizeAttributeName('Birth_Date')).toBe('birthdate');
    expect(normalizeAttributeName('birthDate')).toBe('birthdate');
    expect(normalizeAttributeName('birth-date')).toBe('birthdate');
  });

  it('JSON-LD プレフィックスを落としてローカル名だけを見る', () => {
    expect(normalizeAttributeName('pid:birth_date')).toBe('birthdate');
  });

  it('展開済み IRI（`/` 区切り）のローカル名だけを見る', () => {
    expect(normalizeAttributeName('https://schema.org/birthDate')).toBe('birthdate');
    expect(normalizeAttributeName('http://xmlns.com/foaf/0.1/familyName')).toBe('familyname');
  });

  it('フラグメント形式の IRI（`#` 区切り）のローカル名だけを見る', () => {
    expect(normalizeAttributeName('https://example.org/ns#religion')).toBe('religion');
  });
});

describe('findSpecialCategoryAttributes', () => {
  it.each(REPRESENTATIVE_ATTRIBUTES)('%s を特別カテゴリとして検知する', (key, normalized) => {
    expect(findSpecialCategoryAttributes({ [key]: 'x' })).toEqual([normalized]);
  });

  it('命名揺れ（camelCase / 大文字 / kebab-case）でも検知する', () => {
    expect(findSpecialCategoryAttributes({ birthDate: 'x' })).toEqual(['birthdate']);
    expect(findSpecialCategoryAttributes({ 'Birth-Date': 'x' })).toEqual(['birthdate']);
    expect(findSpecialCategoryAttributes({ NationalID: 'x' })).toEqual(['nationalid']);
  });

  it('JSON-LD プレフィックス付きキーでも検知する', () => {
    expect(findSpecialCategoryAttributes({ 'pid:birth_date': 'x' })).toEqual(['birthdate']);
  });

  it('展開済み IRI キー（`/` / `#` 区切り）でも検知する', () => {
    expect(findSpecialCategoryAttributes({ 'https://schema.org/birthDate': 'x' })).toEqual([
      'birthdate',
    ]);
    expect(findSpecialCategoryAttributes({ 'http://xmlns.com/foaf/0.1/familyName': 'x' })).toEqual([
      'familyname',
    ]);
    expect(findSpecialCategoryAttributes({ 'https://example.org/ns#religion': 'x' })).toEqual([
      'religion',
    ]);
  });

  it('IRI 形式でも無害なキーは検知しない（誤検知しない）', () => {
    expect(
      findSpecialCategoryAttributes({ 'https://example.org/ns/serviceEndpoint': 'x' }),
    ).toEqual([]);
  });

  it('入れ子オブジェクト・配列の内部まで走査する', () => {
    const document = {
      service: [{ id: '#s1', serviceEndpoint: { profile: { religion: 'x' } } }],
    };
    expect(findSpecialCategoryAttributes(document)).toEqual(['religion']);
  });

  it('複数一致を重複なし・辞書順で返す', () => {
    const value = { health: 'x', nested: { race: 'y', health: 'z' } };
    expect(findSpecialCategoryAttributes(value)).toEqual(['health', 'race']);
  });

  it('iso3166_alpha2 プレフィックス付きの値でも属性名で検知する（値では回避できない）', () => {
    expect(findSpecialCategoryAttributes({ national_id: 'iso3166_alpha2:DE-123' })).toEqual([
      'nationalid',
    ]);
  });

  it('循環参照を含む値でも停止する', () => {
    const cyclic: Record<string, unknown> = { religion: 'x' };
    cyclic.self = cyclic;
    expect(findSpecialCategoryAttributes(cyclic)).toEqual(['religion']);
  });

  it('プロトタイプ鎖の汚染値は拾わない', () => {
    const polluted = Object.create({ religion: 'x' }) as Record<string, unknown>;
    polluted.id = 'did:webvh:example';
    expect(findSpecialCategoryAttributes(polluted)).toEqual([]);
  });

  it('W3C DID Core の正規な語彙だけの DID Document は検知しない', () => {
    const document = {
      '@context': ['https://www.w3.org/ns/did/v1'],
      id: 'did:webvh:scid:vericerts.io',
      controller: 'did:webvh:scid:vericerts.io',
      alsoKnownAs: ['did:web:vericerts.io'],
      verificationMethod: [
        { id: '#key-1', type: 'Multikey', controller: '', publicKeyMultibase: 'z6Mk' },
      ],
      authentication: ['#key-1'],
      assertionMethod: ['#key-1'],
      service: [{ id: '#s1', type: 'DIDCommMessaging', serviceEndpoint: 'https://vericerts.io' }],
    };
    expect(findSpecialCategoryAttributes(document)).toEqual([]);
  });

  it('プリミティブ・null・バイナリは走査対象外', () => {
    expect(findSpecialCategoryAttributes(null)).toEqual([]);
    expect(findSpecialCategoryAttributes('religion')).toEqual([]);
    expect(findSpecialCategoryAttributes(new Uint8Array([1, 2, 3]))).toEqual([]);
  });
});

describe('assertNoSpecialCategoryOnChain', () => {
  it('禁止属性を含む場合 GDPR_SPECIAL_CATEGORY_ON_CHAIN(10601) を投げる', () => {
    expect(() => assertNoSpecialCategoryOnChain({ health: 'x' })).toThrow(SPECIAL_CATEGORY);
  });

  it('例外に属性名・値を載せない（PII 非開示）', () => {
    try {
      assertNoSpecialCategoryOnChain({ religion: 'secret-value' });
      throw new Error('should have thrown');
    } catch (error) {
      expect(error).toBeInstanceOf(VericertsError);
      const serialized = JSON.stringify({
        message: (error as VericertsError).message,
        context: (error as VericertsError).context,
      });
      expect(serialized).not.toContain('secret-value');
      expect(serialized).not.toContain('religion');
      expect((error as VericertsError).code).toBe(ErrorCodes.GDPR_SPECIAL_CATEGORY_ON_CHAIN);
    }
  });

  it('禁止属性を含まない場合は何も投げない', () => {
    expect(() => assertNoSpecialCategoryOnChain({ id: 'did:webvh:x' })).not.toThrow();
  });
});

// SDK は発行時と DID Document 更新時に属性を検査する。発行時の
// 経路はチェーンに書き込まないため、10601 ではなく 10607 を送出する。
describe('assertNoSpecialCategoryInIssuedContent', () => {
  it('禁止属性を含む場合 GDPR_SPECIAL_CATEGORY_ISSUANCE(10607) を投げる', () => {
    expect(() => assertNoSpecialCategoryInIssuedContent({ health: 'x' })).toThrow(
      SPECIAL_CATEGORY_ISSUANCE,
    );
  });

  it('オンチェーン用の 10601 とは別コードを送出する', () => {
    // 発行系ファサードはチェーンに書き込まないため `_ON_CHAIN` は発生元として不正確。
    try {
      assertNoSpecialCategoryInIssuedContent({ religion: 'x' });
      throw new Error('should have thrown');
    } catch (error) {
      expect((error as VericertsError).code).not.toBe(ErrorCodes.GDPR_SPECIAL_CATEGORY_ON_CHAIN);
      expect((error as VericertsError).code).toBe(ErrorCodes.GDPR_SPECIAL_CATEGORY_ISSUANCE);
    }
  });

  it('例外に属性名・値を載せない（PII 非開示）', () => {
    try {
      assertNoSpecialCategoryInIssuedContent({ nested: { religion: 'secret-value' } });
      throw new Error('should have thrown');
    } catch (error) {
      expect(error).toBeInstanceOf(VericertsError);
      const serialized = JSON.stringify({
        message: (error as VericertsError).message,
        context: (error as VericertsError).context,
      });
      expect(serialized).not.toContain('secret-value');
      expect(serialized).not.toContain('religion');
      expect((error as VericertsError).code).toBe(ErrorCodes.GDPR_SPECIAL_CATEGORY_ISSUANCE);
    }
  });

  it('禁止属性を含まない場合は何も投げない', () => {
    expect(() => assertNoSpecialCategoryInIssuedContent({ degree: 'BSc' })).not.toThrow();
  });
});

describe('SPECIAL_CATEGORY_ATTRIBUTES', () => {
  it('公開ビューは変更できない（汚染で検知範囲を広げられない）', () => {
    expect(() => (SPECIAL_CATEGORY_ATTRIBUTES as Set<string>).add('nickname')).toThrow(TypeError);
    expect(() => (SPECIAL_CATEGORY_ATTRIBUTES as Set<string>).delete('religion')).toThrow(
      TypeError,
    );
  });

  it('公開ビューを汚染しても判定は動かない', () => {
    try {
      (SPECIAL_CATEGORY_ATTRIBUTES as Set<string>).delete('religion');
    } catch {
      // 変更不能ビューなので失敗する。判定が権威集合を読むことの確認が目的。
    }
    expect(findSpecialCategoryAttributes({ religion: 'x' })).toEqual(['religion']);
  });
});

describe('非列挙の own プロパティ（走査範囲と読み取り範囲の一致）', () => {
  // 値を読む側の `ownProperty` は `Object.hasOwn` 判定なので非列挙でも読む。走査が
  // `Object.keys`（own かつ列挙可能）だけだと検査のほうが狭くなり、
  // `Object.defineProperty(o, 'health', { enumerable: false })` が素通りする。
  // 公開先は追記専用で取り消せないため、広い側（own 全体）へ揃えてある。
  function withNonEnumerable(key: string, value: unknown): Record<string, unknown> {
    const target: Record<string, unknown> = { id: 'did:webvh:example.com:alice' };
    Object.defineProperty(target, key, { value, enumerable: false, configurable: true });
    return target;
  }

  it('非列挙の禁止属性を検知する', () => {
    expect(findSpecialCategoryAttributes(withNonEnumerable('health', 'HIV+'))).toEqual(['health']);
  });

  it('入れ子オブジェクトの非列挙な禁止属性も検知する', () => {
    const nested = { credentialSubject: withNonEnumerable('religion', 'x') };
    expect(findSpecialCategoryAttributes(nested)).toEqual(['religion']);
  });

  it('非列挙の禁止属性を持つ DID Document を 10601 で拒否する', () => {
    expect(() =>
      assertNoSpecialCategoryOnChain(withNonEnumerable('birth_date', '1990-01-01')),
    ).toThrow(VericertsError);
    try {
      assertNoSpecialCategoryOnChain(withNonEnumerable('birth_date', '1990-01-01'));
      throw new Error('should have thrown');
    } catch (error) {
      expect((error as VericertsError).code).toBe(ErrorCodes.GDPR_SPECIAL_CATEGORY_ON_CHAIN);
    }
  });

  it('非列挙でも禁止語彙でなければ検知しない（誤検知しない）', () => {
    expect(findSpecialCategoryAttributes(withNonEnumerable('nickname', 'ali'))).toEqual([]);
  });
});
