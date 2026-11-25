/**
 * フォーマットネゴシエーションのプロトタイプ汚染に対する回帰テスト。
 *
 * 未知の形式の `privacyScore` は 0 とし、フォールバックでも署名スイートの制約を維持する。
 *
 * 塞ぐ欠陥は 2 系統ある。いずれも `format` が Verifier 要求・候補 VC 由来の外部入力である点に起因する。
 *
 * 1. `PRIVACY_TIER` が通常のオブジェクトリテラルだと `PRIVACY_TIER['constructor']` が
 *    `Object.prototype.constructor`（関数）を返し、`?? 0` の未知フォーマットガードをすり抜ける。
 *    合成スコアが `関数 * 100` = `NaN` になり、比較関数が非全順序化して候補のソート結果が不定になる。
 * 2. Verifier 要求表を `requested[format]` で引くと `Object.prototype` のメンバがヒットし、
 *    Verifier が要求していないフォーマットの VC が「制約を満たす」と判定される。返る値は `alg` を
 *    持たないためダウングレード拒否まで素通りする。
 *
 * 検証は到達可能なモジュール API（`selectBestVC` / `canFulfillFormats` /
 * `evaluateFormatCapability`）経由で行い、module-private なスコア関数には触れない。
 */

import { describe, expect, test } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import { SD_JWT_VC_TYP } from '../../sdjwt/typ.js';
import { evaluateFormatCapability, type FormatDescriptor } from '../capability.js';
import { canFulfillFormats, selectBestVC } from '../select.js';
import {
  type NegotiableCredential,
  PRIVACY_TIER,
  SELECTIVE_DISCLOSURE_FORMATS,
  type VpFormatRequirement,
} from '../types.js';

/** `Object.prototype` 側に同名メンバが存在するフォーマット識別子（攻撃者が自由に名乗れる値）。 */
const PROTOTYPE_FORMATS = ['constructor', 'toString', 'valueOf', 'hasOwnProperty', '__proto__'];

/** 決定的タイブレーク（シャッフルで入力順を維持する側の極値）。 */
const keepOrder = () => 0.999_999;

/** 決定的タイブレーク（シャッフルで入力順を反転させる側の極値）。 */
const reverseOrder = () => 0;

function vc(
  overrides: Partial<NegotiableCredential> & { id: string; format: string },
): NegotiableCredential {
  return { alg: 'ES256', ...overrides } as NegotiableCredential;
}

/** 汚染操作を実行し、投げられた例外を返す（投げない実装でも呼び出しを継続させる）。 */
function captureError(attempt: () => unknown): unknown {
  try {
    attempt();
  } catch (error) {
    return error;
  }
  return undefined;
}

describe('要求されていないプロトタイプ由来 format の候補は適合しない', () => {
  for (const format of PROTOTYPE_FORMATS) {
    test(`format="${format}" の候補しかなければ 3050 で拒否される`, () => {
      const requested: VpFormatRequirement = { jwt_vc_json: {} };
      const candidates = [vc({ id: 'junk-1', format })];
      expect(() => selectBestVC(requested, candidates, { randomTiebreak: keepOrder })).toThrow(
        new VericertsError(ErrorCodes.VP_FORMATS_NOT_SUPPORTED),
      );
    });
  }

  test('正当な候補と混在しても、プロトタイプ由来 format は候補に残らない', () => {
    const requested: VpFormatRequirement = { jwt_vc_json: { alg: ['ES256'] } };
    const candidates = [
      vc({ id: 'junk-1', format: 'constructor' }),
      vc({ id: 'jwt-1', format: 'jwt_vc_json' }),
      vc({ id: 'junk-2', format: 'toString' }),
    ];
    const result = selectBestVC(requested, candidates, { randomTiebreak: keepOrder });
    expect(result.chosen.id).toBe('jwt-1');
    expect(result.alternatives).toEqual([]);
  });
});

describe('署名スイート降格の拒否をすり抜けない', () => {
  test('要求は ES256、format="constructor" / alg="none" の候補は 3050 で拒否される', () => {
    const requested: VpFormatRequirement = { jwt_vc_json: { alg: ['ES256'] } };
    const candidates = [vc({ id: 'downgraded', format: 'constructor', alg: 'none' })];
    let thrown: unknown;
    try {
      selectBestVC(requested, candidates, { randomTiebreak: keepOrder });
    } catch (error) {
      thrown = error;
    }
    expect(thrown).toBeInstanceOf(VericertsError);
    expect((thrown as VericertsError).code).toBe(ErrorCodes.VP_FORMATS_NOT_SUPPORTED);
  });
});

describe('プロトタイプ由来 format が合成スコアを NaN にしない', () => {
  // 双方とも要求表の「自身のプロパティ」なので、junk 候補も正当に候補集合へ入り privacyScore に
  // 到達する。dc+sd-jwt が先頭＝フォーマット優先度で必ず勝つはずであり、スコアが NaN でなければ
  // シャッフル順に関わらず結果は一意に決まる。
  const requested: VpFormatRequirement = { [SD_JWT_VC_TYP]: {}, constructor: {} };
  const genuine = vc({ id: 'sd-1', format: SD_JWT_VC_TYP });
  const junk = vc({ id: 'junk-1', format: 'constructor' });

  const orders: ReadonlyArray<readonly [string, readonly NegotiableCredential[]]> = [
    ['正順', [genuine, junk]],
    ['逆順', [junk, genuine]],
  ];
  const tiebreaks: ReadonlyArray<readonly [string, () => number]> = [
    ['入力順維持', keepOrder],
    ['入力順反転', reverseOrder],
  ];

  for (const [orderLabel, candidates] of orders) {
    for (const [tiebreakLabel, randomTiebreak] of tiebreaks) {
      test(`候補${orderLabel} × タイブレーク${tiebreakLabel} でも dc+sd-jwt が選ばれる`, () => {
        const result = selectBestVC(requested, candidates, { randomTiebreak });
        expect(result.chosen.id).toBe('sd-1');
        expect(result.alternatives.map((a) => a.id)).toEqual(['junk-1']);
      });
    }
  }
});

describe('被覆判定・capability 評価もプロトタイプ由来 format を通さない', () => {
  test('要求フォーマットは unmatched に落ち、descriptor も満たせないと報告される', () => {
    const vpFormats: VpFormatRequirement = { jwt_vc_json: { alg: ['ES256'] } };
    const candidates = [vc({ id: 'junk-1', format: 'constructor', alg: 'none' })];

    const coverage = canFulfillFormats(vpFormats, candidates);
    expect(coverage.fullyCovered).toBe(false);
    expect(coverage.matchedFormats).toEqual([]);
    expect(coverage.unmatchedFormats).toEqual(['jwt_vc_json']);

    const descriptors: FormatDescriptor[] = [{ id: 'pid', vpFormats, candidates }];
    const result = evaluateFormatCapability(descriptors, { randomTiebreak: keepOrder });
    expect(result.fullyCovered).toBe(false);
    expect(result.selections).toEqual([]);
    expect(result.unmatchedDescriptors).toEqual(['pid']);
  });

  test('要求 format 自体がプロトタイプ由来でも、別名のプロトタイプ由来候補では満たせない', () => {
    // `constructor` は要求表の自身のプロパティなので正当な要求。これを満たせるのは実際に
    // `constructor` を名乗る VC だけであり、`toString` を名乗る別の VC が肩代わりしてはならない。
    const vpFormats: VpFormatRequirement = { constructor: { alg: ['ES256'] } };
    const candidates = [
      vc({ id: 'jwt-1', format: 'jwt_vc_json' }),
      vc({ id: 'junk-1', format: 'toString' }),
    ];

    const coverage = canFulfillFormats(vpFormats, candidates);
    expect(coverage.fullyCovered).toBe(false);
    expect(coverage.matchedFormats).toEqual([]);
    expect(coverage.unmatchedFormats).toEqual(['constructor']);

    const descriptors: FormatDescriptor[] = [{ id: 'pid', vpFormats, candidates }];
    const result = evaluateFormatCapability(descriptors, { randomTiebreak: keepOrder });
    expect(result.fullyCovered).toBe(false);
    expect(result.selections).toEqual([]);
    expect(result.unmatchedDescriptors).toEqual(['pid']);
  });
});

describe('SELECTIVE_DISCLOSURE_FORMATS は変更不能ビューである', () => {
  test('読み取り操作は従来どおり動く（非破壊的変更であることの表明）', () => {
    expect([...SELECTIVE_DISCLOSURE_FORMATS].sort()).toEqual(
      ['bbs+', 'dc+sd-jwt', 'mso_mdoc', 'vc+sd-jwt'].sort(),
    );
    expect(SELECTIVE_DISCLOSURE_FORMATS.has(SD_JWT_VC_TYP)).toBe(true);
    expect(SELECTIVE_DISCLOSURE_FORMATS.has('jwt_vc_json')).toBe(false);
    expect(SELECTIVE_DISCLOSURE_FORMATS.size).toBe(4);
    expect(new Set(SELECTIVE_DISCLOSURE_FORMATS).size).toBe(4);
  });

  test('直接変更もプロトタイプ経由の汚染も TypeError で拒否され、中身は無傷', () => {
    // 拒否が効かない実装でも「中身が無傷か」の表明まで到達させるため、throw をその場で待たない。
    const errors = [
      captureError(() => (SELECTIVE_DISCLOSURE_FORMATS as Set<string>).add('jwt_vc_json')),
      captureError(() => Set.prototype.add.call(SELECTIVE_DISCLOSURE_FORMATS, 'jwt_vc_json')),
      captureError(() => (SELECTIVE_DISCLOSURE_FORMATS as Set<string>).delete(SD_JWT_VC_TYP)),
      captureError(() => (SELECTIVE_DISCLOSURE_FORMATS as Set<string>).clear()),
    ];
    for (const error of errors) {
      expect(error).toBeInstanceOf(TypeError);
    }
    expect(SELECTIVE_DISCLOSURE_FORMATS.has('jwt_vc_json')).toBe(false);
    expect(SELECTIVE_DISCLOSURE_FORMATS.has(SD_JWT_VC_TYP)).toBe(true);
    expect(SELECTIVE_DISCLOSURE_FORMATS.size).toBe(4);
  });

  test('forEach のコールバック第 3 引数から可変な実体が漏れない', () => {
    // 素の `Set.prototype.forEach` は `this`（＝ビューが包む可変 `Set`）を第 3 引数に渡すため、
    // 実体に束縛したままだとコールバック内から公開集合を恒久的に広げられてしまう。
    const errors: unknown[] = [];
    SELECTIVE_DISCLOSURE_FORMATS.forEach((_format, _format2, set) => {
      expect(set).toBe(SELECTIVE_DISCLOSURE_FORMATS);
      errors.push(captureError(() => (set as Set<string>).add('jwt_vc_json')));
    });
    expect(errors).toHaveLength(4);
    for (const error of errors) {
      expect(error).toBeInstanceOf(TypeError);
    }
    expect(SELECTIVE_DISCLOSURE_FORMATS.has('jwt_vc_json')).toBe(false);
    expect(SELECTIVE_DISCLOSURE_FORMATS.size).toBe(4);
  });
});

describe('既知フォーマットの挙動は変わらない', () => {
  test('PRIVACY_TIER はプロトタイプを持たず、既知エントリのスコアは spec どおり', () => {
    expect(Object.getPrototypeOf(PRIVACY_TIER)).toBeNull();
    expect(PRIVACY_TIER['bbs+']).toBe(100);
    expect(PRIVACY_TIER['dc+sd-jwt']).toBe(80);
    expect(PRIVACY_TIER['vc+sd-jwt']).toBe(80);
    expect(PRIVACY_TIER.mso_mdoc).toBe(70);
    expect(PRIVACY_TIER.ldp_vc).toBe(50);
    expect(PRIVACY_TIER['vc+cose']).toBe(40);
    expect(PRIVACY_TIER.jwt_vc_json).toBe(30);
    expect(PRIVACY_TIER['jwt_vc_json-ld']).toBe(30);
  });

  test('PRIVACY_TIER 由来のプライバシー優先度は従来どおり効く', () => {
    // 同一フォーマット＝フォーマット優先度・alg 優先度は同点。tier 80 の sd-jwt が
    // supportsSelectiveDisclosure=false で 30 まで落ちることでのみ差がつく。
    const requested: VpFormatRequirement = { [SD_JWT_VC_TYP]: { alg: ['ES256'] } };
    const candidates = [
      vc({ id: 'sd-off', format: SD_JWT_VC_TYP, supportsSelectiveDisclosure: false }),
      vc({ id: 'sd-on', format: SD_JWT_VC_TYP, supportsSelectiveDisclosure: true }),
    ];
    const result = selectBestVC(requested, candidates, { randomTiebreak: keepOrder });
    expect(result.chosen.id).toBe('sd-on');
    expect(result.alternatives.map((a) => a.id)).toEqual(['sd-off']);
  });
});
