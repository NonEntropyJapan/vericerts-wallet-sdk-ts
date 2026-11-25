/**
 * PEx 評価の fail-open 是正の回帰テスト。
 *
 * - SDK 非対応 format（`mso_mdoc` / `jwt_vc` 等）しか要求しない記述子はどの VC にもマッチしない。
 * - 評価できないフィルタキーワードは捨てずに不一致にし、数値・文字列長の範囲は評価する。
 * - `const` / `enum` は配列・object も深い等価で比較する。
 */

import { describe, expect, it } from 'bun:test';
import type { QueryableCredential } from '../../auth/dcql/dcql.js';
import { ErrorCodes, type VericertsError } from '../../errors.js';
import { parsePresentationDefinition } from '../definition.js';
import { evaluatePresentationDefinition } from '../evaluate.js';

function definitionWith(descriptor: Record<string, unknown>) {
  return parsePresentationDefinition({ id: 'pd-1', input_descriptors: [descriptor] });
}

function matchCount(
  path: string,
  filter: Record<string, unknown>,
  claims: Record<string, unknown>,
): number {
  const pd = definitionWith({ id: 'd1', constraints: { fields: [{ path: [path], filter }] } });
  return evaluatePresentationDefinition(pd, [{ id: 'x', format: 'dc+sd-jwt', claims }]).length;
}

const sdJwt: QueryableCredential = { id: 'x', format: 'dc+sd-jwt', claims: { a: 1 } };

describe('SDK 非対応の format 要件は fail-closed', () => {
  it.each([
    'mso_mdoc',
    'jwt_vc',
    'jwt_vp',
    'ldp_vp',
    'ac_vc',
  ])('%s だけを要求する記述子にはどの format の VC もマッチしない', (key) => {
    const pd = definitionWith({
      id: 'd',
      format: { [key]: { alg: ['ES256'] } },
      constraints: { fields: [{ path: ['$.a'] }] },
    });
    expect(evaluatePresentationDefinition(pd, [sdJwt])).toEqual([]);
    expect(
      evaluatePresentationDefinition(pd, [{ ...sdJwt, id: 'y', format: 'jwt_vc_json' }]),
    ).toEqual([]);
  });

  it('非対応 format の記述子が候補を持たなくても、別の記述子の評価は継続する', () => {
    const pd = parsePresentationDefinition({
      id: 'pd-1',
      input_descriptors: [
        {
          id: 'mdoc',
          format: { mso_mdoc: { alg: ['ES256'] } },
          constraints: { fields: [{ path: ['$.a'] }] },
        },
        { id: 'any', constraints: { fields: [{ path: ['$.a'] }] } },
      ],
    });
    expect(evaluatePresentationDefinition(pd, [sdJwt]).map((m) => m.queryId)).toEqual(['any']);
  });

  it('既知 format と非対応 format を併記した要件は、既知 format の VC だけにマッチする', () => {
    const pd = definitionWith({
      id: 'd',
      format: { mso_mdoc: {}, 'dc+sd-jwt': { alg: ['ES256'] } },
      constraints: { fields: [{ path: ['$.a'] }] },
    });
    expect(evaluatePresentationDefinition(pd, [sdJwt])).toHaveLength(1);
    expect(
      evaluatePresentationDefinition(pd, [{ ...sdJwt, id: 'y', format: 'jwt_vc_json' }]),
    ).toEqual([]);
  });

  it('真に空の format: {} は従来どおり制約なし', () => {
    const pd = definitionWith({
      id: 'd',
      format: {},
      constraints: { fields: [{ path: ['$.a'] }] },
    });
    expect(evaluatePresentationDefinition(pd, [sdJwt])).toHaveLength(1);
  });
});

describe('filter の未対応キーワードは fail-closed', () => {
  const claims = { age: 10, name: 'ab' };

  it.each([
    ['$.name', { type: 'string', not: { const: 'ab' } }],
    ['$.name', { type: 'string', format: 'date' }],
    ['$.name', { type: 'string', multipleOf: 2 }],
    ['$.age', { type: 'number', multipleOf: 5 }],
    ['$.name', { type: 'string', items: {} }],
  ])('%s に %j を要求するとマッチしない（黙って捨てない）', (path, filter) => {
    expect(matchCount(path, filter, claims)).toBe(0);
  });

  it('注釈（title / description / $comment 等）だけなら制約として扱わない', () => {
    expect(
      matchCount('$.name', { type: 'string', title: 't', description: 'd', $comment: 'c' }, claims),
    ).toBe(1);
  });

  it('未対応キーワードを持つ filter は optional で値が無い場合だけ通る', () => {
    const pd = definitionWith({
      id: 'd1',
      constraints: {
        fields: [
          { path: ['$.missing'], optional: true, filter: { type: 'string', format: 'date' } },
        ],
      },
    });
    expect(evaluatePresentationDefinition(pd, [{ ...sdJwt, claims }])).toHaveLength(1);
  });
});

describe('filter の範囲キーワード', () => {
  const claims = { age: 10, name: 'ab', emoji: '😀😀' };

  it.each([
    ['$.age', { type: 'number', minimum: 18 }, 0],
    ['$.age', { type: 'number', minimum: 10 }, 1],
    ['$.age', { type: 'number', exclusiveMinimum: 10 }, 0],
    ['$.age', { type: 'number', exclusiveMinimum: 9 }, 1],
    ['$.age', { type: 'number', maximum: 5 }, 0],
    ['$.age', { type: 'number', maximum: 10 }, 1],
    ['$.age', { type: 'number', exclusiveMaximum: 10 }, 0],
    ['$.age', { type: 'integer', minimum: 5, maximum: 20 }, 1],
    ['$.name', { type: 'string', minLength: 5 }, 0],
    ['$.name', { type: 'string', minLength: 2, maxLength: 2 }, 1],
    ['$.name', { type: 'string', maxLength: 1 }, 0],
    // コードポイント数（UTF-16 コードユニット数ではない）
    ['$.emoji', { type: 'string', maxLength: 2 }, 1],
    ['$.emoji', { type: 'string', minLength: 3 }, 0],
  ])('%s に %j → %i 件', (path, filter, expected) => {
    expect(matchCount(path, filter, claims)).toBe(expected);
  });

  it.each([
    ['minimum', '18'],
    ['maxLength', null],
    ['exclusiveMinimum', true],
    ['minLength', Number.POSITIVE_INFINITY],
  ])('%s に数値以外（%j）を指定した定義は 8030 で拒否する', (keyword, bound) => {
    let error: unknown;
    try {
      definitionWith({
        id: 'd',
        constraints: {
          fields: [{ path: ['$.age'], filter: { type: 'number', [keyword]: bound } }],
        },
      });
    } catch (e) {
      error = e;
    }
    expect((error as VericertsError).code).toBe(ErrorCodes.OID4VP_REQUEST_PARSE_FAILED);
  });
});

describe('filter.const / enum は深い等価で比較する', () => {
  const claims = { tags: ['a', 'b'], addr: { c: 'JP', n: { z: 1 } }, name: 'x' };

  it.each([
    ['$.tags', { type: 'array', const: ['a', 'b'] }, 1],
    ['$.tags', { type: 'array', const: ['b', 'a'] }, 0],
    ['$.tags', { type: 'array', enum: [['x'], ['a', 'b']] }, 1],
    ['$.tags', { type: 'array', enum: [['a']] }, 0],
    ['$.addr', { type: 'object', const: { n: { z: 1 }, c: 'JP' } }, 1],
    ['$.addr', { type: 'object', const: { c: 'JP' } }, 0],
    ['$.addr', { type: 'object', enum: [{ c: 'US', n: { z: 1 } }] }, 0],
    ['$.addr.c', { type: 'string', const: 'JP' }, 1],
    ['$.name', { type: 'string', enum: ['y', 'x'] }, 1],
    ['$.name', { type: 'string', enum: ['y'] }, 0],
  ])('%s に %j → %i 件', (path, filter, expected) => {
    expect(matchCount(path, filter, claims)).toBe(expected);
  });
});
