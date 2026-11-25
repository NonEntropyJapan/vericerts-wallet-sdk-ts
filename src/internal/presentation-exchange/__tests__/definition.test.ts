/**
 * Presentation Definition パースのユニットテスト。
 *
 * 検証内容:
 * - parsePresentationDefinition: 正常系（name / purpose / format / filter / optional の構造化）。
 * - id 欠落 / input_descriptors 欠落・空 / 記述子 id 重複 / constraints 欠落 / Field.path 不正で 8030。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes, type VericertsError } from '../../errors.js';
import { parsePresentationDefinition } from '../definition.js';

/** 8030（OID4VP_REQUEST_PARSE_FAILED）で失敗することを表明する。 */
function expectParseFailure(raw: Record<string, unknown>): void {
  try {
    parsePresentationDefinition(raw);
    throw new Error('should have thrown');
  } catch (err) {
    expect((err as VericertsError).code).toBe(ErrorCodes.OID4VP_REQUEST_PARSE_FAILED);
  }
}

describe('parsePresentationDefinition', () => {
  it('id / input_descriptors / constraints を構造化する', () => {
    const pd = parsePresentationDefinition({
      id: 'pd-1',
      name: 'Age check',
      purpose: 'verify age',
      input_descriptors: [
        {
          id: 'age',
          name: 'Age credential',
          purpose: 'age',
          format: { 'dc+sd-jwt': { alg: ['ES256'] } },
          constraints: {
            limit_disclosure: 'required',
            fields: [
              {
                path: ['$.credentialSubject.age', '$.age'],
                filter: { type: 'number', const: 20 },
                optional: false,
              },
            ],
          },
        },
      ],
    });

    expect(pd.id).toBe('pd-1');
    expect(pd.name).toBe('Age check');
    expect(pd.purpose).toBe('verify age');
    expect(pd.input_descriptors).toHaveLength(1);
    const descriptor = pd.input_descriptors[0];
    expect(descriptor?.format?.['dc+sd-jwt']?.alg).toEqual(['ES256']);
    expect(descriptor?.constraints.limit_disclosure).toBe('required');
    expect(descriptor?.constraints.fields[0]?.path).toEqual(['$.credentialSubject.age', '$.age']);
    expect(descriptor?.constraints.fields[0]?.filter?.const).toBe(20);
    expect(descriptor?.constraints.fields[0]?.optional).toBe(false);
  });

  it('任意メンバを省略しても構造化できる', () => {
    const pd = parsePresentationDefinition({
      id: 'pd-2',
      input_descriptors: [{ id: 'd1', constraints: { fields: [{ path: ['$.vct'] }] } }],
    });
    expect(pd.name).toBeUndefined();
    expect(pd.input_descriptors[0]?.format).toBeUndefined();
    expect(pd.input_descriptors[0]?.constraints.fields[0]?.filter).toBeUndefined();
  });

  it('id 欠落で 8030', () => {
    expectParseFailure({ input_descriptors: [{ id: 'd1', constraints: { fields: [] } }] });
  });

  it('input_descriptors 欠落で 8030', () => {
    expectParseFailure({ id: 'pd-1' });
  });

  it('input_descriptors が空配列で 8030', () => {
    expectParseFailure({ id: 'pd-1', input_descriptors: [] });
  });

  it('input_descriptors が配列でないと 8030', () => {
    expectParseFailure({ id: 'pd-1', input_descriptors: {} });
  });

  it('記述子の id 重複で 8030', () => {
    expectParseFailure({
      id: 'pd-1',
      input_descriptors: [
        { id: 'dup', constraints: { fields: [] } },
        { id: 'dup', constraints: { fields: [] } },
      ],
    });
  });

  it('constraints 欠落で 8030', () => {
    expectParseFailure({ id: 'pd-1', input_descriptors: [{ id: 'd1' }] });
  });

  it('constraints.fields 欠落で 8030', () => {
    expectParseFailure({ id: 'pd-1', input_descriptors: [{ id: 'd1', constraints: {} }] });
  });

  it('Field.path が空配列で 8030', () => {
    expectParseFailure({
      id: 'pd-1',
      input_descriptors: [{ id: 'd1', constraints: { fields: [{ path: [] }] } }],
    });
  });

  it('Field.path が文字列配列でないと 8030', () => {
    expectParseFailure({
      id: 'pd-1',
      input_descriptors: [{ id: 'd1', constraints: { fields: [{ path: [42] }] } }],
    });
  });

  it('Field.path の要素が空文字列で 8030', () => {
    expectParseFailure({
      id: 'pd-1',
      input_descriptors: [{ id: 'd1', constraints: { fields: [{ path: [''] }] } }],
    });
  });

  it('filter.type 欠落で 8030', () => {
    expectParseFailure({
      id: 'pd-1',
      input_descriptors: [
        { id: 'd1', constraints: { fields: [{ path: ['$.a'], filter: { pattern: '^a$' } }] } },
      ],
    });
  });

  it('filter.pattern が 512 文字を超えると 8030', () => {
    const fieldWith = (pattern: string) => ({
      id: 'pd-1',
      input_descriptors: [
        {
          id: 'd1',
          constraints: { fields: [{ path: ['$.a'], filter: { type: 'string', pattern } }] },
        },
      ],
    });
    expectParseFailure(fieldWith('a'.repeat(513)));
    expect(() => parsePresentationDefinition(fieldWith('a'.repeat(512)))).not.toThrow();
  });

  it('limit_disclosure が未知の値で 8030', () => {
    expectParseFailure({
      id: 'pd-1',
      input_descriptors: [{ id: 'd1', constraints: { fields: [], limit_disclosure: 'always' } }],
    });
  });

  it('プロトタイプ汚染由来の constraints は未指定として扱い 8030', () => {
    const polluted = Object.create({ constraints: { fields: [] } }) as Record<string, unknown>;
    polluted.id = 'd1';
    expectParseFailure({ id: 'pd-1', input_descriptors: [polluted] });
  });
});
