/**
 * `parameters.witness` の検証（did:webvh v1.0、spec: The `witness` Parameter、The DID Log File の「検証に失敗する例」1）。
 * 不正な witness 構成は「witness なし」と見なさず、署名検証の前にエラーにする。
 */

import { afterEach, describe, expect, it } from 'bun:test';
import { forgeGenesis, generateKey, restoreFetch, signEntry } from '../webvh-fixtures.js';
import { INVALID_DID, resolveLog, signedGenesis, witnessKey } from './log-builders.js';

afterEach(() => {
  restoreFetch();
});

const w1 = witnessKey();
const w2 = witnessKey();

describe('parameters.witness の値の検証', () => {
  const cases: [string, Record<string, unknown>][] = [
    [
      '重複する witness id（spec 検証例 1）',
      { threshold: 1, witnesses: [{ id: w1.id }, { id: w1.id }] },
    ],
    ['threshold が 0', { threshold: 0, witnesses: [{ id: w1.id }] }],
    [
      'threshold が witness の件数を超える',
      { threshold: 3, witnesses: [{ id: w1.id }, { id: w2.id }] },
    ],
    [
      'threshold が重複を除いた件数を超える',
      { threshold: 2, witnesses: [{ id: w1.id }, { id: w1.id }] },
    ],
    ['threshold がない', { witnesses: [{ id: w1.id }] }],
    ['threshold が小数', { threshold: 1.5, witnesses: [{ id: w1.id }, { id: w2.id }] }],
    ['threshold が文字列', { threshold: '1', witnesses: [{ id: w1.id }] }],
    ['witnesses が空', { threshold: 1, witnesses: [] }],
    ['witnesses がない', { threshold: 1 }],
    ['witness に weight（v1.0 で廃止）', { threshold: 1, witnesses: [{ id: w1.id, weight: 1 }] }],
    ['witness 構成に未知のメンバ', { threshold: 1, witnesses: [{ id: w1.id }], extra: true }],
    ['witness id が did:key でない', { threshold: 1, witnesses: [{ id: 'did:web:example.com' }] }],
    [
      'witness id が Ed25519 でない did:key',
      {
        threshold: 1,
        witnesses: [{ id: 'did:key:zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme' }],
      },
    ],
    [
      'witness id にフラグメント',
      { threshold: 1, witnesses: [{ id: `${w1.id}#${w1.id.slice(8)}` }] },
    ],
    ['witness id が文字列でない', { threshold: 1, witnesses: [{ id: 1 }] }],
    ['witnesses が配列でない', { threshold: 1, witnesses: { id: w1.id } }],
  ];
  it.each(cases)('%s は、witness なしと見なされず拒否される', async (_label, witness) => {
    const key = generateKey();
    const { did, entry } = forgeGenesis({ key, parameters: { witness } });
    await expect(resolveLog(did, [signEntry(entry, key)])).rejects.toThrow(INVALID_DID);
  });

  it('生成側（createDidWebVh）も同じ不正を署名前に拒否する', () => {
    for (const [, witness] of cases) {
      expect(() => signedGenesis({ witness: witness as never })).toThrow(INVALID_DID);
    }
  });

  it('witness: {} は witness なしの明示で、メタデータは空のオブジェクト', async () => {
    const { did, genesis } = signedGenesis({ witness: {} });
    const { metadata } = await resolveLog(did, [genesis]);
    expect(metadata.witness).toEqual({});
  });
});
