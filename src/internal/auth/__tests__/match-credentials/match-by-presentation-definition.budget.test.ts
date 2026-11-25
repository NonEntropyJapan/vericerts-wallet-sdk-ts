/**
 * `matchCredentialsByPresentationDefinition` の評価量予算の回帰テスト。
 *
 * PEx の JSONPath 走査量予算・正規表現ステップ予算の単位は Presentation Request 1 件。保持 VC を
 * 1 件ずつ評価する経路でも予算は全 VC で共有され、VC の件数に比例して上限が増えない。
 * 実時間ではなく「予算を使い切った後の VC が不一致になる」ことで共有を pin する。
 */

import { describe, expect, it } from 'bun:test';
import type { VerifiableCredential } from '../../../credential/index.js';
import {
  createPexBudget,
  type PexBudget,
  parsePresentationDefinition,
} from '../../../presentation-exchange/index.js';
import { matchCredentialsByPresentationDefinition } from '../../match-by-presentation-definition.js';

function makeVc(id: string, credentialSubject: Record<string, unknown>): VerifiableCredential {
  return {
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    type: ['VerifiableCredential'],
    issuer: 'did:example:issuer',
    credentialSubject,
    issuanceDate: '2025-01-01T00:00:00Z',
    id,
  };
}

/** 深さ `depth` の入れ子（`$..*..*..*..*` の評価量が爆発する形）。 */
function deepSubject(depth: number): Record<string, unknown> {
  let node: Record<string, unknown> = { leaf: 1 };
  for (let i = 0; i < depth; i += 1) {
    node = { a: node, b: [1] };
  }
  return node;
}

/** JSONPath 読み出し予算だけを絞った予算（実物の上限を踏ませると評価が秒単位になるため注入する）。 */
function budgetWithPathReads(remaining: number): PexBudget {
  const budget = createPexBudget();
  budget.paths.remaining = remaining;
  return budget;
}

const heavyPathDefinition = parsePresentationDefinition({
  id: 'pd-1',
  input_descriptors: [
    { id: 'd1', constraints: { fields: [{ path: ['$..*..*..*..*', '$..name'] }] } },
  ],
});

/** 深さ 8 の heavy VC は `$..*..*..*..*` に約 5 万の予算（読み出し + 深さ加算）を要する（TIGHT 未満では打ち切られ、WIDE なら完走する）。 */
const TIGHT_READS = 1_000;
const WIDE_READS = 200_000;

describe('matchCredentialsByPresentationDefinition の評価量予算は全 VC で共有される', () => {
  const heavy = makeVc('urn:vc:heavy', deepSubject(8));
  const light = makeVc('urn:vc:light', { name: 'Alice' });

  it('前提: light VC は小さい予算でも一致し、heavy VC は小さい予算では超過・十分な予算では一致する', () => {
    expect(
      matchCredentialsByPresentationDefinition(
        heavyPathDefinition,
        [light],
        budgetWithPathReads(TIGHT_READS),
      ),
    ).toHaveLength(1);

    const tight = budgetWithPathReads(TIGHT_READS);
    expect(matchCredentialsByPresentationDefinition(heavyPathDefinition, [heavy], tight)).toEqual(
      [],
    );
    expect(tight.paths.exhausted).toBe(true);

    const wide = budgetWithPathReads(WIDE_READS);
    expect(
      matchCredentialsByPresentationDefinition(heavyPathDefinition, [heavy], wide),
    ).toHaveLength(1);
    expect(wide.paths.exhausted).toBe(false);
    expect(WIDE_READS - wide.paths.remaining).toBeGreaterThan(TIGHT_READS);
  });

  it('heavy VC が予算を使い切った後は、後続の light VC も不一致になる', () => {
    const budget = budgetWithPathReads(TIGHT_READS);
    const matched = matchCredentialsByPresentationDefinition(
      heavyPathDefinition,
      [heavy, light],
      budget,
    );
    expect(matched).toEqual([]);
    expect(budget.paths.exhausted).toBe(true);
  });

  it('予算を使い切る前に評価された VC は一致する（順序依存の fail-closed）', () => {
    const matched = matchCredentialsByPresentationDefinition(
      heavyPathDefinition,
      [light, heavy],
      budgetWithPathReads(TIGHT_READS),
    );
    expect(matched.map((vc) => vc.id)).toEqual(['urn:vc:light']);
  });
});
