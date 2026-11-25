/**
 * `parentEdges()` の親エッジフィールド own 限定読み取りの回帰テスト。
 *
 * `vc[field]`（`derivedFrom` / `supersedes` / `amends` / `basedOn`）はプロトタイプ鎖を辿っていた。
 * VC 本文は呼び出し側が渡す入力であり、これらのフィールドを**一切宣言していない**単発 VC
 * （チェーンに参加しない VC）でも `Object.prototype` 汚染下では継承値を親 ID として拾う。
 * その結果、
 *
 * - `verifyCredentialChain` が無関係な親 ID を解決しにいって失敗し可用性を落とす、
 * - `revocationPropagation` の伝搬判定が攻撃者の選んだ関係種別で捻じ曲がる、
 *
 * といった形で壊れる。同じ `chain/` モジュールの `build.ts` / `verify.ts` は既に
 * `ownProperty` へ統一済みで、`edges.ts` だけが未対応だった。
 *
 * データプロパティ汚染とアクセサ（getter）汚染の両方を検証する。`vc[field] === undefined` や
 * 汚染値との同一性比較で塞ぐ実装は、getter が呼ばれるたびに別の値を返す汚染で素通りするため。
 *
 * **トートロジー回避**: own 値と汚染値を食い違わせ、own として明示宣言した親エッジは汚染下でも
 * 従来どおり拾われることまで検証する。
 */

import { describe, expect, it } from 'bun:test';
import {
  withPollutedPrototype,
  withPollutedPrototypeAccessor,
} from '../../../../__tests__/prototype-pollution.fixtures.js';
import type { VerifiableCredential } from '../../../vc/vc.js';
import { type ParentEdge, parentEdges } from '../../edges.js';

const V2_CONTEXT = 'https://www.w3.org/ns/credentials/v2';
const ATTACKER_ID = 'urn:uuid:attacker-parent';
const REAL_PARENT_ID = 'urn:uuid:real-parent';

/** 親エッジフィールドを own に持たない最小 VC（`own` を渡した分だけ own プロパティを生やす）。 */
function makeVc(own: Readonly<Record<string, unknown>> = {}): VerifiableCredential {
  return {
    '@context': [V2_CONTEXT],
    type: ['VerifiableCredential'],
    issuer: 'did:example:issuer',
    credentialSubject: { id: 'did:example:holder' },
    issuanceDate: '2026-01-01T00:00:00Z',
    id: 'urn:uuid:standalone',
    ...own,
  } as unknown as VerifiableCredential;
}

describe('parentEdges の親エッジフィールドは own 限定', () => {
  it('derivedFrom のデータ汚染は親エッジに混入しない', () => {
    const edges = withPollutedPrototype({ derivedFrom: ATTACKER_ID }, () => parentEdges(makeVc()));

    expect(edges).toEqual([]);
  });

  it('derivedFrom のアクセサ汚染も親エッジに混入しない', () => {
    const edges = withPollutedPrototypeAccessor({ derivedFrom: () => ATTACKER_ID }, () =>
      parentEdges(makeVc()),
    );

    expect(edges).toEqual([]);
  });

  it('supersedes / amends / basedOn のデータ汚染も親エッジに混入しない', () => {
    for (const field of ['supersedes', 'amends', 'basedOn'] as const) {
      const edges = withPollutedPrototype({ [field]: ATTACKER_ID }, () => parentEdges(makeVc()));

      expect(edges).toEqual([]);
    }
  });

  it('basedOn の配列汚染（複数 ID）も親エッジに混入しない', () => {
    const edges = withPollutedPrototype({ basedOn: [ATTACKER_ID, 'urn:uuid:attacker-2'] }, () =>
      parentEdges(makeVc()),
    );

    expect(edges).toEqual([]);
  });

  it('4 フィールドを同時に汚染しても親エッジは空のまま', () => {
    const edges = withPollutedPrototype(
      {
        derivedFrom: ATTACKER_ID,
        supersedes: ATTACKER_ID,
        amends: ATTACKER_ID,
        basedOn: ATTACKER_ID,
      },
      () => parentEdges(makeVc()),
    );

    expect(edges).toEqual([]);
  });

  it('対照: own に宣言した親エッジは汚染下でも従来どおり拾われる（own 値が勝つ）', () => {
    const expected: ParentEdge[] = [{ id: REAL_PARENT_ID, relation: 'derivedFrom' }];

    const edges = withPollutedPrototype({ derivedFrom: ATTACKER_ID, amends: ATTACKER_ID }, () =>
      parentEdges(makeVc({ derivedFrom: REAL_PARENT_ID })),
    );

    expect(edges).toEqual(expected);
  });

  it('対照: own に宣言した親エッジはアクセサ汚染下でも拾われる', () => {
    const expected: ParentEdge[] = [{ id: REAL_PARENT_ID, relation: 'amends' }];

    const edges = withPollutedPrototypeAccessor({ derivedFrom: () => ATTACKER_ID }, () =>
      parentEdges(makeVc({ amends: REAL_PARENT_ID })),
    );

    expect(edges).toEqual(expected);
  });

  it('対照: 汚染なしで親エッジフィールドを持たない VC は空配列', () => {
    expect(parentEdges(makeVc())).toEqual([]);
  });
});
