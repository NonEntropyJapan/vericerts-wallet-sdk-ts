/**
 * evaluateFormatCapability の公開エクスポート面を検証する。
 * 利用者がメインバレルから呼び出し、descriptor 配列から FormatCapabilityResult を同期的に得られることを確認する。
 */

import { describe, expect, test } from 'bun:test';
import * as sdk from '../../index.js';

describe('公開エクスポート: evaluateFormatCapability', () => {
  test('メインバレルから関数として import できる', () => {
    expect(typeof sdk.evaluateFormatCapability).toBe('function');
  });

  test('descriptor 配列・同期シグネチャで動作する（型だけの再エクスポートではない）', () => {
    const descriptors: sdk.FormatDescriptor[] = [
      {
        id: 'pid',
        vpFormats: { 'vc+sd-jwt': { alg: ['ES256'] } },
        candidates: [{ id: 'sd-1', format: 'vc+sd-jwt', alg: 'ES256' }],
      },
      {
        id: 'mdl',
        vpFormats: { mso_mdoc: { alg: ['ES256'] } },
        candidates: [{ id: 'sd-2', format: 'vc+sd-jwt', alg: 'ES256' }],
      },
    ];

    const result: sdk.FormatCapabilityResult = sdk.evaluateFormatCapability(descriptors, {
      randomTiebreak: () => 0,
    });

    // 判定結果を同期的に返す。
    expect(result).not.toBeInstanceOf(Promise);
    expect(result.fullyCovered).toBe(false);
    expect(result.selections.map((s) => s.chosen.id)).toEqual(['sd-1']);
    expect(result.unmatchedDescriptors).toEqual(['mdl']);
  });
});
