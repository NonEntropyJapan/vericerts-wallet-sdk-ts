/**
 * format-negotiation の仕事量予算の回帰テスト。
 *
 * `vp_formats` の制約配列長 A × フォーマット数 K × 記述子数 D × 候補 VC 数 C の積が、評価の最小単位
 * （制約 1 件・スコア 1 回・比較 1 回・候補 1 件）の入口で共有予算を消費することを、実時間ではなく
 * 決定的な予算の残量・例外種別で pin する。形状（少数の巨大要素 / 多数の極小要素）を変えて同じ予算が効くことを確かめる。
 */

import { describe, expect, it, setDefaultTimeout } from 'bun:test';
import { HEAVY_INPUT_TIMEOUT_MS } from '../../../__tests__/heavy-input-timeout.js';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import { evaluateFormatCapability, type FormatDescriptor } from '../capability.js';
import { satisfiesRequirement } from '../constraints.js';
import { canFulfillFormats } from '../coverage.js';
import { scoreCredential } from '../scoring.js';
import { selectBestVC } from '../select.js';
import type { NegotiableCredential, VpFormatRequirement } from '../types.js';
import {
  createFormatWorkBudget,
  FORMAT_WORK_EXCEEDED_REASON,
  MAX_FORMAT_WORK_UNITS,
} from '../work.js';

setDefaultTimeout(HEAVY_INPUT_TIMEOUT_MS);

const algs = (count: number) => Array.from({ length: count }, (_, i) => `a${i}`);

function candidates(count: number, alg: string): NegotiableCredential[] {
  return Array.from({ length: count }, (_, i) => ({
    id: `c${i}`,
    format: 'jwt_vc_json',
    alg,
    issuanceDate: '2026-01-01T00:00:00Z',
  }));
}

function expectBudgetError(fn: () => unknown): void {
  try {
    fn();
  } catch (error) {
    expect(error).toBeInstanceOf(VericertsError);
    expect((error as VericertsError).code).toBe(ErrorCodes.VP_FORMATS_NOT_SUPPORTED);
    expect((error as VericertsError).context).toEqual({ reason: FORMAT_WORK_EXCEEDED_REASON });
    return;
  }
  throw new Error('expected the format work budget to be exceeded');
}

describe('最小単位の計上', () => {
  it('satisfiesRequirement: 候補 1 件の固定費 1 + 制約配列 1 本あたり 2 × 長さ', () => {
    const budget = createFormatWorkBudget();
    const requested: VpFormatRequirement = {
      jwt_vc_json: { alg: algs(10), proof_type: ['x', 'y'] },
    };
    const vc: NegotiableCredential = { id: 'c', format: 'jwt_vc_json', alg: 'a9', proofType: 'y' };
    expect(satisfiesRequirement(vc, requested, budget)).toBe(true);
    expect(MAX_FORMAT_WORK_UNITS - budget.remaining).toBe(1 + 2 * 10 + 2 * 2);
  });

  it('制約の無い要求でも候補 1 件の判定は固定費 1 を計上する', () => {
    const budget = createFormatWorkBudget();
    satisfiesRequirement({ id: 'c', format: 'jwt_vc_json' }, { jwt_vc_json: {} }, budget);
    satisfiesRequirement({ id: 'c', format: 'ldp_vc' }, { jwt_vc_json: {} }, budget);
    expect(MAX_FORMAT_WORK_UNITS - budget.remaining).toBe(2);
  });

  it('scoreCredential: 呼び出し 1 回 + フォーマットキー数 + alg 配列長を計上する', () => {
    const budget = createFormatWorkBudget();
    const requested: VpFormatRequirement = {
      jwt_vc_json: { alg: algs(7) },
      'dc+sd-jwt': {},
    };
    scoreCredential({ id: 'c', format: 'jwt_vc_json', alg: 'a3' }, requested, budget);
    expect(MAX_FORMAT_WORK_UNITS - budget.remaining).toBe(1 + 2 + 7);
  });

  it('canFulfillFormats: フォーマット 1 件ごとに保持 VC 全件ぶんの走査を計上する', () => {
    const budget = createFormatWorkBudget();
    canFulfillFormats(
      { jwt_vc_json: {}, 'dc+sd-jwt': {}, mso_mdoc: {} },
      candidates(5, 'ES256'),
      budget,
    );
    // 3 フォーマット × (保持 5 + 1) + 一致候補 1 件の判定（jwt_vc_json だけが一致）の固定費 1。
    expect(MAX_FORMAT_WORK_UNITS - budget.remaining).toBe(3 * 6 + 1);
  });
});

describe('予算を超えると 3050 (format_work_budget_exceeded) で fail-closed', () => {
  // 形状 1: 少数の巨大要素（記述子 1 件・制約配列が巨大）。
  it('単一記述子 × alg 配列 100,000 件 × 候補 30 件（selectBestVC）', () => {
    const requested: VpFormatRequirement = { jwt_vc_json: { alg: algs(100_000) } };
    expectBudgetError(() => selectBestVC(requested, candidates(30, 'a99999')));
  });

  it('単一記述子 × alg 配列 100,000 件（evaluateFormatCapability は descriptor 失敗に倒さず例外にする）', () => {
    const requested: VpFormatRequirement = { jwt_vc_json: { alg: algs(100_000) } };
    const descriptors: FormatDescriptor[] = [
      { id: 'd', vpFormats: requested, candidates: candidates(30, 'a99999') },
    ];
    expectBudgetError(() => evaluateFormatCapability(descriptors));
  });

  // 形状 2: 多数の極小要素（共有 vpFormats を指す記述子を並べる）。
  it('記述子 3,000 件が同じ vp_formats（alg 20 件）を共有し、候補 100 件ずつ', () => {
    const vpFormats: VpFormatRequirement = { jwt_vc_json: { alg: algs(20) } };
    const cands = candidates(100, 'a19');
    const descriptors: FormatDescriptor[] = Array.from({ length: 3_000 }, (_, i) => ({
      id: `d${i}`,
      vpFormats,
      candidates: cands,
    }));
    expectBudgetError(() => evaluateFormatCapability(descriptors, { randomTiebreak: () => 0 }));
  });

  // 形状 3: 巨大な候補配列を共有する記述子を少数並べる（制約が空でも候補の走査量が積まれる）。
  it('候補 5 万件を共有する記述子 100 件でも、候補の走査量で頭打ちになる', () => {
    const vpFormats: VpFormatRequirement = { jwt_vc_json: {} };
    const cands = candidates(50_000, 'ES256');
    const descriptors: FormatDescriptor[] = Array.from({ length: 100 }, (_, i) => ({
      id: `d${i}`,
      vpFormats,
      candidates: cands,
    }));
    expectBudgetError(() => evaluateFormatCapability(descriptors, { randomTiebreak: () => 0 }));
  });

  // 形状 4: フォーマットキーを多数並べる。
  it('フォーマットキー 60,000 個 × 保持 VC 100 件（canFulfillFormats）', () => {
    const required: VpFormatRequirement = Object.fromEntries(
      Array.from({ length: 60_000 }, (_, i) => [`f${i}`, {}]),
    );
    expectBudgetError(() => canFulfillFormats(required, candidates(100, 'ES256')));
  });

  it('予算が尽きた後の再呼び出しも同じ予算を共有して即座に 3050', () => {
    const budget = createFormatWorkBudget();
    const requested: VpFormatRequirement = { jwt_vc_json: { alg: algs(100_000) } };
    expectBudgetError(() => selectBestVC(requested, candidates(30, 'a99999'), { budget }));
    expect(budget.exhausted).toBe(true);
    expectBudgetError(() => selectBestVC({ jwt_vc_json: {} }, candidates(1, 'ES256'), { budget }));
  });
});

describe('通常規模は従来どおり動く', () => {
  it('記述子 50 件 × 候補 50 件 × alg 数件', () => {
    const vpFormats: VpFormatRequirement = {
      'dc+sd-jwt': { alg: ['ES256', 'ES384'] },
      jwt_vc_json: { alg: ['ES256', 'EdDSA'] },
    };
    const cands = candidates(50, 'ES256');
    const descriptors: FormatDescriptor[] = Array.from({ length: 50 }, (_, i) => ({
      id: `d${i}`,
      vpFormats,
      candidates: cands,
    }));
    const result = evaluateFormatCapability(descriptors, { randomTiebreak: () => 0 });
    expect(result.selections).toHaveLength(50);
    expect(result.unmatchedDescriptors).toEqual([]);
  });

  it('要求を満たせない descriptor は従来どおり unmatched（予算エラーにならない）', () => {
    const result = evaluateFormatCapability([
      {
        id: 'd',
        vpFormats: { jwt_vc_json: { alg: ['EdDSA'] } },
        candidates: candidates(3, 'ES256'),
      },
    ]);
    expect(result.unmatchedDescriptors).toEqual(['d']);
  });
});
