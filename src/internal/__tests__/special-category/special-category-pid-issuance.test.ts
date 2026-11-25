/**
 * SDK の発行処理は、PID 生データの属性名を 10607 で拒否する。
 * ARF では加盟国指定の PID Provider が PID を発行する。PID Rulebook の必須属性は
 * SDK の発行ガードの禁止語彙に含まれる。一方、(Q)EAA には固定の必須属性集合がなく、
 * 禁止語彙を使わないものは発行可能である。
 *
 * ここでは発行時のガードとオンチェーン書き込み時のガードが同じ PID 属性を拒否すること、
 * 生データを含まない代替属性は通ることを固定する。一般の正規化・走査範囲とエラーの
 * PII 非開示は special-category.test.ts で検証する。
 */

import { describe, expect, it } from 'bun:test';
import { type ErrorCode, ErrorCodes, VericertsError } from '../../errors.js';
import {
  assertNoSpecialCategoryInIssuedContent,
  assertNoSpecialCategoryOnChain,
  normalizeAttributeName,
  SPECIAL_CATEGORY_ATTRIBUTES,
} from '../../special-category.js';

/**
 * `fn` が `VericertsError` を投げ、その `code` が `expected` と一致することを表明する。
 *
 * メッセージ一致（`toThrow(new VericertsError(...))`）では 10601 と 10607 を取り違えても
 * 文言が違う間だけ偶然通ってしまい、文言の推敲で静かに判別力を失う。コードを直接見ることで
 * 「どちらのガードが発火したか」を文言に依存せず固定する。
 */
function expectErrorCode(fn: () => unknown, expected: ErrorCode): void {
  try {
    fn();
  } catch (error) {
    expect(error).toBeInstanceOf(VericertsError);
    expect((error as VericertsError).code).toBe(expected);
    return;
  }
  throw new Error(`VericertsError(${expected}) が投げられなかった`);
}

/** SDK の発行ガードが対象とする PID 生データの属性名。 */
const PID_RAW_ATTRIBUTES = ['family_name', 'given_name', 'birth_date', 'birth_place'] as const;

describe('PID 生データの Issue 時拒否（本 SDK のスコープ外）', () => {
  for (const attribute of PID_RAW_ATTRIBUTES) {
    it(`Issue 時ガードが \`${attribute}\` を 10607 で拒否する`, () => {
      expectErrorCode(
        () => assertNoSpecialCategoryInIssuedContent({ [attribute]: 'x' }),
        ErrorCodes.GDPR_SPECIAL_CATEGORY_ISSUANCE,
      );
    });
  }

  it('受領した PID をそのまま再発行しようとするクレームを拒否する', () => {
    expectErrorCode(
      () =>
        assertNoSpecialCategoryInIssuedContent({
          credentialSubject: {
            family_name: 'Doe',
            given_name: 'Jane',
            birth_date: '1990-01-01',
            issuing_country: 'DE',
          },
        }),
      ErrorCodes.GDPR_SPECIAL_CATEGORY_ISSUANCE,
    );
  });

  it('禁止語彙に PID 生データの 4 属性が含まれ続ける', () => {
    for (const attribute of PID_RAW_ATTRIBUTES) {
      expect(SPECIAL_CATEGORY_ATTRIBUTES.has(normalizeAttributeName(attribute))).toBe(true);
    }
  });
});

describe('禁止語彙の公開ビューをオンチェーン側と発行側の双方が拒否する', () => {
  // 2 つのコードの違いは発生元（オンチェーン投下・DID Document 更新か、VC 発行か）を
  // 正確に示すためだけの区別であり、禁止語彙の集合は同一である。
  // ただしここで実測できるのは「公開ビュー `SPECIAL_CATEGORY_ATTRIBUTES` の全要素を双方が拒否する」
  // という一方向だけである。逆向き（双方が拒否する名前は必ず公開ビューに載る）は名前空間が
  // 無限で悉皆検証できないため、代表的な非禁止属性名での標本検証（下の it）に留める。
  it('公開ビューの全語彙をオンチェーン側と発行側の双方が拒否する', () => {
    // 語彙が空になるとループが 1 度も回らず vacuous pass するため、集合が非空であることを先に固定する。
    expect(SPECIAL_CATEGORY_ATTRIBUTES.size).toBeGreaterThan(0);
    for (const normalized of SPECIAL_CATEGORY_ATTRIBUTES) {
      const payload = { [normalized]: 'x' };
      expectErrorCode(
        () => assertNoSpecialCategoryOnChain(payload),
        ErrorCodes.GDPR_SPECIAL_CATEGORY_ON_CHAIN,
      );
      expectErrorCode(
        () => assertNoSpecialCategoryInIssuedContent(payload),
        ErrorCodes.GDPR_SPECIAL_CATEGORY_ISSUANCE,
      );
    }
  });

  it('語彙に無い属性名はオンチェーン側も発行側も拒否しない', () => {
    // データ最小化の代替（`age_over_18` / `nickname` 等）が双方で通ることも
    // ここで併せて確認する。PID 生データの拒否は「PID 相当の情報を一切扱えない」ことを意味しない。
    const payload = { nickname: 'jd', age_over_18: true, degree: 'BSc' };
    expect(() => assertNoSpecialCategoryOnChain(payload)).not.toThrow();
    expect(() => assertNoSpecialCategoryInIssuedContent(payload)).not.toThrow();
  });
});
