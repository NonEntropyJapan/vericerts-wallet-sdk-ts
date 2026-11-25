/**
 * Presentation Definition 評価のユニットテスト。
 *
 * 検証内容:
 * - format 要件の一致 / 不一致（未対応 format でも throw せず候補から外れること）。
 * - path 候補を先頭から試し最初の一致を採用すること。
 * - filter（type / pattern / const / enum）の一致 / 不一致。
 * - optional フィールドが解決できない場合の扱い。
 * - 同一記述子に複数クレデンシャルがマッチした場合に全件返ること。
 */

import { describe, expect, it, setDefaultTimeout } from 'bun:test';
import { HEAVY_INPUT_TIMEOUT_MS } from '../../__tests__/heavy-input-timeout.js';
import type { QueryableCredential } from '../../auth/dcql/dcql.js';
import { parsePresentationDefinition } from '../definition.js';
import { evaluatePresentationDefinition } from '../evaluate.js';

setDefaultTimeout(HEAVY_INPUT_TIMEOUT_MS);

/** 単一 Input Descriptor の Definition を組み立てる。 */
function definitionWith(descriptor: Record<string, unknown>) {
  return parsePresentationDefinition({ id: 'pd-1', input_descriptors: [descriptor] });
}

const alice: QueryableCredential = {
  id: 'vc-alice',
  format: 'dc+sd-jwt',
  vct: 'https://example.com/pid',
  claims: { credentialSubject: { name: 'Alice', age: 20, email: 'alice@example.com' } },
};

const bob: QueryableCredential = {
  id: 'vc-bob',
  format: 'jwt_vc_json',
  claims: { credentialSubject: { name: 'Bob', age: 17 } },
};

describe('evaluatePresentationDefinition', () => {
  it('format が一致するクレデンシャルだけを候補にする', () => {
    const pd = definitionWith({
      id: 'd1',
      format: { 'dc+sd-jwt': { alg: ['ES256'] } },
      constraints: { fields: [{ path: ['$.credentialSubject.name'] }] },
    });
    const matches = evaluatePresentationDefinition(pd, [alice, bob]);
    expect(matches).toEqual([
      { credentialId: 'vc-alice', queryId: 'd1', matchedClaims: ['$.credentialSubject.name'] },
    ]);
  });

  it('format 未指定なら format を問わない', () => {
    const pd = definitionWith({
      id: 'd1',
      constraints: { fields: [{ path: ['$.credentialSubject.name'] }] },
    });
    const matches = evaluatePresentationDefinition(pd, [alice, bob]);
    expect(matches.map((m) => m.credentialId)).toEqual(['vc-alice', 'vc-bob']);
  });

  it('未対応 format を要求されても throw せず候補が空になるだけ', () => {
    const pd = definitionWith({
      id: 'd1',
      format: { ldp_vc: { proof_type: ['Ed25519Signature2020'] } },
      constraints: { fields: [{ path: ['$.credentialSubject.name'] }] },
    });
    expect(evaluatePresentationDefinition(pd, [alice, bob])).toEqual([]);
  });

  it('複数の Input Descriptor は 1 つが非対応でも残りを評価する', () => {
    const pd = parsePresentationDefinition({
      id: 'pd-1',
      input_descriptors: [
        {
          id: 'unsupported',
          format: { ldp_vc: { proof_type: ['Ed25519Signature2020'] } },
          constraints: { fields: [{ path: ['$.credentialSubject.name'] }] },
        },
        { id: 'any', constraints: { fields: [{ path: ['$.credentialSubject.name'] }] } },
      ],
    });
    const matches = evaluatePresentationDefinition(pd, [alice]);
    expect(matches).toHaveLength(1);
    expect(matches[0]?.queryId).toBe('any');
  });

  it('path 候補を先頭から試し最初に解決できた path を採用する', () => {
    const pd = definitionWith({
      id: 'd1',
      constraints: {
        fields: [{ path: ['$.missing', '$.credentialSubject.email', '$.credentialSubject.name'] }],
      },
    });
    const matches = evaluatePresentationDefinition(pd, [alice]);
    expect(matches[0]?.matchedClaims).toEqual(['$.credentialSubject.email']);
  });

  it('どの path も解決できなければ不一致', () => {
    const pd = definitionWith({
      id: 'd1',
      constraints: { fields: [{ path: ['$.missing', '$.alsoMissing'] }] },
    });
    expect(evaluatePresentationDefinition(pd, [alice])).toEqual([]);
  });

  it('optional なフィールドは解決できなくても不一致にせず matchedClaims にも載せない', () => {
    const pd = definitionWith({
      id: 'd1',
      constraints: {
        fields: [
          { path: ['$.credentialSubject.name'] },
          { path: ['$.credentialSubject.nickname'], optional: true },
        ],
      },
    });
    const matches = evaluatePresentationDefinition(pd, [alice]);
    expect(matches).toHaveLength(1);
    expect(matches[0]?.matchedClaims).toEqual(['$.credentialSubject.name']);
  });

  it('filter.type が一致しないと不一致', () => {
    const pd = definitionWith({
      id: 'd1',
      constraints: { fields: [{ path: ['$.credentialSubject.age'], filter: { type: 'string' } }] },
    });
    expect(evaluatePresentationDefinition(pd, [alice])).toEqual([]);
  });

  it('filter.pattern の一致 / 不一致', () => {
    const matching = definitionWith({
      id: 'd1',
      constraints: {
        fields: [
          {
            path: ['$.credentialSubject.email'],
            filter: { type: 'string', pattern: '@example\\.com$' },
          },
        ],
      },
    });
    expect(evaluatePresentationDefinition(matching, [alice])).toHaveLength(1);

    const notMatching = definitionWith({
      id: 'd1',
      constraints: {
        fields: [
          {
            path: ['$.credentialSubject.email'],
            filter: { type: 'string', pattern: '@other\\.test$' },
          },
        ],
      },
    });
    expect(evaluatePresentationDefinition(notMatching, [alice])).toEqual([]);
  });

  it('filter.const の一致 / 不一致', () => {
    const matching = definitionWith({
      id: 'd1',
      constraints: {
        fields: [{ path: ['$.credentialSubject.age'], filter: { type: 'number', const: 20 } }],
      },
    });
    expect(evaluatePresentationDefinition(matching, [alice])).toHaveLength(1);

    const notMatching = definitionWith({
      id: 'd1',
      constraints: {
        fields: [{ path: ['$.credentialSubject.age'], filter: { type: 'number', const: 21 } }],
      },
    });
    expect(evaluatePresentationDefinition(notMatching, [alice])).toEqual([]);
  });

  it('filter.enum の一致 / 不一致', () => {
    const matching = definitionWith({
      id: 'd1',
      constraints: {
        fields: [
          {
            path: ['$.credentialSubject.name'],
            filter: { type: 'string', enum: ['Alice', 'Carol'] },
          },
        ],
      },
    });
    expect(evaluatePresentationDefinition(matching, [alice])).toHaveLength(1);

    const notMatching = definitionWith({
      id: 'd1',
      constraints: {
        fields: [
          { path: ['$.credentialSubject.name'], filter: { type: 'string', enum: ['Carol'] } },
        ],
      },
    });
    expect(evaluatePresentationDefinition(notMatching, [alice])).toEqual([]);
  });

  it('不正な正規表現 pattern は throw せず不一致に倒す', () => {
    const pd = definitionWith({
      id: 'd1',
      constraints: {
        fields: [{ path: ['$.credentialSubject.name'], filter: { type: 'string', pattern: '(' } }],
      },
    });
    expect(evaluatePresentationDefinition(pd, [alice])).toEqual([]);
  });

  it('同一記述子に複数クレデンシャルがマッチしたら全件返す', () => {
    const pd = definitionWith({
      id: 'd1',
      constraints: { fields: [{ path: ['$.credentialSubject.name'] }] },
    });
    const matches = evaluatePresentationDefinition(pd, [alice, bob]);
    expect(matches).toHaveLength(2);
    expect(matches.map((m) => m.credentialId)).toEqual(['vc-alice', 'vc-bob']);
  });

  it('fields が空なら format だけで候補になる', () => {
    const pd = definitionWith({
      id: 'd1',
      format: { jwt_vc_json: { alg: ['ES256'] } },
      constraints: { fields: [] },
    });
    const matches = evaluatePresentationDefinition(pd, [alice, bob]);
    expect(matches).toEqual([{ credentialId: 'vc-bob', queryId: 'd1', matchedClaims: [] }]);
  });

  describe('filter.pattern の ReDoS 耐性', () => {
    const claimCredential = (value: string): QueryableCredential => ({
      id: 'c1',
      format: 'dc+sd-jwt',
      claims: { name: value },
    });
    const patternDefinition = (pattern: string) =>
      definitionWith({
        id: 'd1',
        constraints: { fields: [{ path: ['$.name'], filter: { type: 'string', pattern } }] },
      });

    it.each([
      ['^(a+)+$', `${'a'.repeat(40)}!`],
      ['^(.|.)*x$', 'Alice Example Holder-Name 1990 Alice Example'],
      ['^(a*){10}b', 'a'.repeat(40)],
      ['^(?:a?){28}a{28}$', 'a'.repeat(27)],
      ['^(a+){30}$', `${'a'.repeat(40)}!`],
    ])('%s は即座に返り不一致になる', (pattern, value) => {
      const startedAt = performance.now();
      const matches = evaluatePresentationDefinition(patternDefinition(pattern), [
        claimCredential(value),
      ]);
      expect(matches).toEqual([]);
      expect(performance.now() - startedAt).toBeLessThan(1_000);
    });

    it('通常のパターンは一致する', () => {
      const matches = evaluatePresentationDefinition(patternDefinition('^(a*){10}b'), [
        claimCredential('aaab'),
      ]);
      expect(matches).toHaveLength(1);
    });

    it('後方参照・先読みを含む pattern は評価せず不一致（fail-closed）', () => {
      for (const pattern of ['^(a)\\1$', '^(?=a)a$']) {
        expect(
          evaluatePresentationDefinition(patternDefinition(pattern), [claimCredential('aa')]),
        ).toEqual([]);
      }
    });

    it('評価ステップの総量予算を使い切った後の pattern は不一致になり、時間も有界', () => {
      const credentials = Array.from({ length: 200 }, (_, i) => ({
        ...claimCredential('a'.repeat(100_000)),
        id: `c${i}`,
      }));
      const startedAt = performance.now();
      const matches = evaluatePresentationDefinition(patternDefinition('^[a-z]+$'), credentials);
      expect(matches.length).toBeLessThan(credentials.length);
      expect(performance.now() - startedAt).toBeLessThan(5_000);
    });
  });

  describe('不正な JSONPath は raw Error を漏らさない', () => {
    const goodAndBad = (path: string) =>
      definitionWith({ id: 'd1', constraints: { fields: [{ path: [path] }] } });

    it.each([
      '$[?(@.x==1',
      '$[(1+1)]',
      '$[?(@.__proto__)]',
      '$..[?(@.constructor)]',
    ])('%s は throw せず不一致として扱い、他クレデンシャルの評価を継続する', (path) => {
      const broken: QueryableCredential = {
        id: 'broken',
        format: 'dc+sd-jwt',
        claims: { name: 'a', a: { b: 1 } },
      };
      expect(() => evaluatePresentationDefinition(goodAndBad(path), [broken, alice])).not.toThrow();
      expect(evaluatePresentationDefinition(goodAndBad(path), [broken, alice])).toEqual([]);
    });

    it('不正な path の後ろにある正しい path 候補は採用される', () => {
      const pd = definitionWith({
        id: 'd1',
        constraints: { fields: [{ path: ['$[?(@.x==1', '$.credentialSubject.name'] }] },
      });
      expect(evaluatePresentationDefinition(pd, [alice])).toEqual([
        { credentialId: 'vc-alice', queryId: 'd1', matchedClaims: ['$.credentialSubject.name'] },
      ]);
    });

    it('optional なフィールドの不正 path は条件なしとして扱う', () => {
      const pd = definitionWith({
        id: 'd1',
        constraints: { fields: [{ path: ['$[(1+1)]'], optional: true }] },
      });
      expect(evaluatePresentationDefinition(pd, [alice])).toHaveLength(1);
    });
  });
});
