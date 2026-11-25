/**
 * 発行オプションが own の `__proto__` データプロパティを持っても正規化が壊れないことの
 * 回帰テスト。
 *
 * `normalizeIssueOptions` は `Object.getOwnPropertyNames(opts)` の各キーを写す。写し先が
 * `{}` リテラルなので `__proto__` の setter を継承しており、**生代入 `snapshot[key] = …` だと
 * `opts` の own `__proto__` がその setter を発火させた**。帰結は 2 つで、どちらも
 * 保証を無効化する。
 *
 * 1. そのオプションがスナップショットから静かに消える。
 * 2. `snapshot` のプロトタイプが**攻撃者のオブジェクト**になるため、`deepSnapshot` の
 *    `isPlainContainer` 判定（プロトタイプが `Object.prototype` / `null` / `Array.prototype`）が
 *    偽になり、**入れ子を畳まずにそのまま返す**。結果、`opts` について入れ子アクセサの
 *    二重評価ドリフトと 10607 Art.9 ガードのすり抜けが復活する。
 *
 * `Object.defineProperty`（`internal/prototype-safety/define-data-property.ts` の `defineDataProperty`）は
 * `__proto__` でも通常の own データプロパティを作るため、どちらも起きない。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import {
  assertNoSpecialCategoryInIssuedContent,
  findSpecialCategoryAttributes,
} from '../../../special-category.js';
import type { IssueOptions } from '../../module/issue-options.js';
import { normalizeIssueOptions } from '../../module/normalized-issue-input.js';

const SPECIAL_CATEGORY = new VericertsError(ErrorCodes.GDPR_SPECIAL_CATEGORY_ISSUANCE);

/** own の `__proto__` データプロパティを持つ発行オプションを組み立てる。 */
function optionsWithProtoKey(protoValue: unknown): IssueOptions {
  const opts: Record<string, unknown> = { expirationDate: '2027-01-01T00:00:00Z' };
  // 生代入では setter が発火してしまうため、フィクスチャ側も defineProperty で仕込む
  // （攻撃者は `Object.defineProperty` でも null プロトタイプ由来の spread でも到達できる）。
  Object.defineProperty(opts, '__proto__', {
    value: protoValue,
    writable: true,
    enumerable: true,
    configurable: true,
  });
  return opts as unknown as IssueOptions;
}

describe('normalizeIssueOptions は own __proto__ でプロトタイプを差し替えられない', () => {
  it('スナップショットのプロトタイプが攻撃者のオブジェクトにならない', () => {
    const attackerProto = { poisoned: true };

    const snapshot = normalizeIssueOptions(optionsWithProtoKey(attackerProto));

    expect(Object.getPrototypeOf(snapshot)).toBe(Object.prototype);
    expect((snapshot as unknown as Record<string, unknown>).poisoned).toBeUndefined();
  });

  it('__proto__ は通常の own データプロパティとして写る（静かに消えない）', () => {
    const snapshot = normalizeIssueOptions(optionsWithProtoKey({ poisoned: true }));

    expect(Object.hasOwn(snapshot, '__proto__')).toBe(true);
    expect(Object.hasOwn(snapshot, 'expirationDate')).toBe(true);
  });

  it('プロトタイプが差し替わらないので入れ子アクセサは従来どおり畳まれる', () => {
    // プロトタイプが攻撃者のオブジェクトになると `isPlainContainer` が偽になり、
    // `deepSnapshot` が畳まずに返す（= 入れ子 getter が生き残る）。
    let reads = 0;
    const evidence: Record<string, unknown> = {};
    Object.defineProperty(evidence, 'detail', {
      configurable: true,
      enumerable: true,
      get(): unknown {
        reads += 1;
        return reads === 1 ? { ok: 1 } : { health: 'HIV+' };
      },
    });
    const opts = optionsWithProtoKey({ poisoned: true }) as unknown as Record<string, unknown>;
    opts.evidence = evidence;

    const snapshot = normalizeIssueOptions(opts as unknown as IssueOptions);

    expect(reads).toBe(1);
    expect(JSON.stringify(snapshot)).not.toContain('healthData');
    expect(JSON.stringify(snapshot)).not.toContain('health"');
    // 何度直列化しても 1 回目の確定値のまま。
    expect(JSON.stringify(snapshot)).toBe(JSON.stringify(snapshot));
    expect(reads).toBe(1);
  });

  it('Art.9 ガードは own __proto__ を持つオプションでも入れ子まで効く', () => {
    const opts = optionsWithProtoKey({ poisoned: true }) as unknown as Record<string, unknown>;
    opts.evidence = { profile: { diagnosis: 'HIV+' } };

    const snapshot = normalizeIssueOptions(opts as unknown as IssueOptions);

    // 走査器から入れ子の Art.9 属性名が見えること（10607 の判定材料が残っていること）。
    expect(findSpecialCategoryAttributes(snapshot)).toContain('diagnosis');
    expect(() => assertNoSpecialCategoryInIssuedContent([snapshot])).toThrow(SPECIAL_CATEGORY);
  });
});
