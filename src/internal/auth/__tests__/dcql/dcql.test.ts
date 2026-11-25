/**
 * DCQL クエリのパース・評価のユニットテスト。
 *
 * 検証内容:
 * - parseDcqlQuery: 正常系 / credentials 欠落・空 / id 重複 / claim path 不正で 8030。
 * - evaluateDcql: format / vct_values / path 存在 / values 一致による絞り込み。
 * - 未対応 format で 8050（FORMAT_NEGOTIATION_FAILED）。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import { evaluateDcql, parseDcqlQuery, type QueryableCredential } from '../../dcql/dcql.js';

describe('parseDcqlQuery', () => {
  it('format / meta / claims を構造化する', () => {
    const query = parseDcqlQuery({
      credentials: [
        {
          id: 'pid',
          format: 'vc+sd-jwt',
          meta: { vct_values: ['https://example.com/pid'] },
          claims: [{ path: ['given_name'] }, { path: ['age'], values: [18, 19, 20] }],
        },
      ],
    });
    expect(query.credentials).toHaveLength(1);
    const cred = query.credentials[0];
    expect(cred?.format).toBe('vc+sd-jwt');
    expect(cred?.meta?.vct_values).toEqual(['https://example.com/pid']);
    expect(cred?.claims).toHaveLength(2);
    expect(cred?.claims?.[1]?.values).toEqual([18, 19, 20]);
  });

  it('credentials が配列でないと 8030', () => {
    try {
      parseDcqlQuery({ credentials: {} as unknown as [] });
      throw new Error('should have thrown');
    } catch (err) {
      expect((err as VericertsError).code).toBe(ErrorCodes.OID4VP_REQUEST_PARSE_FAILED);
    }
  });

  it('credentials が空配列で 8030', () => {
    try {
      parseDcqlQuery({ credentials: [] });
      throw new Error('should have thrown');
    } catch (err) {
      expect((err as VericertsError).code).toBe(ErrorCodes.OID4VP_REQUEST_PARSE_FAILED);
    }
  });

  it('id / format 欠落で 8030', () => {
    try {
      parseDcqlQuery({ credentials: [{ id: 'x' }] });
      throw new Error('should have thrown');
    } catch (err) {
      expect((err as VericertsError).code).toBe(ErrorCodes.OID4VP_REQUEST_PARSE_FAILED);
    }
  });

  it('credential id 重複で 8030', () => {
    try {
      parseDcqlQuery({
        credentials: [
          { id: 'dup', format: 'jwt_vc_json' },
          { id: 'dup', format: 'vc+sd-jwt' },
        ],
      });
      throw new Error('should have thrown');
    } catch (err) {
      expect((err as VericertsError).code).toBe(ErrorCodes.OID4VP_REQUEST_PARSE_FAILED);
    }
  });

  it('claim path が空配列で 8030', () => {
    try {
      parseDcqlQuery({
        credentials: [{ id: 'x', format: 'jwt_vc_json', claims: [{ path: [] }] }],
      });
      throw new Error('should have thrown');
    } catch (err) {
      expect((err as VericertsError).code).toBe(ErrorCodes.OID4VP_REQUEST_PARSE_FAILED);
    }
  });

  it('claim values が配列でないと 8030', () => {
    try {
      parseDcqlQuery({
        credentials: [{ id: 'x', format: 'jwt_vc_json', claims: [{ path: ['a'], values: 'x' }] }],
      });
      throw new Error('should have thrown');
    } catch (err) {
      expect((err as VericertsError).code).toBe(ErrorCodes.OID4VP_REQUEST_PARSE_FAILED);
    }
  });
});

describe('evaluateDcql', () => {
  const sdJwtCred: QueryableCredential = {
    id: 'urn:cred:1',
    format: 'vc+sd-jwt',
    vct: 'https://example.com/pid',
    claims: { given_name: 'Alice', age: 30, address: { country: 'JP' } },
  };
  const jwtVcCred: QueryableCredential = {
    id: 'urn:cred:2',
    format: 'jwt_vc_json',
    claims: { credentialSubject: { name: 'Bob' } },
  };

  it('format / vct / path がすべて一致したら候補になる', () => {
    const query = parseDcqlQuery({
      credentials: [
        {
          id: 'q1',
          format: 'vc+sd-jwt',
          meta: { vct_values: ['https://example.com/pid'] },
          claims: [{ path: ['given_name'] }, { path: ['address', 'country'] }],
        },
      ],
    });
    const matches = evaluateDcql(query, [sdJwtCred, jwtVcCred]);
    expect(matches).toHaveLength(1);
    expect(matches[0]?.credentialId).toBe('urn:cred:1');
    expect(matches[0]?.queryId).toBe('q1');
    expect(matches[0]?.matchedClaims).toEqual(['given_name', 'address.country']);
  });

  it('vct_values 不一致は候補にならない', () => {
    const query = parseDcqlQuery({
      credentials: [
        { id: 'q1', format: 'vc+sd-jwt', meta: { vct_values: ['https://example.com/other'] } },
      ],
    });
    expect(evaluateDcql(query, [sdJwtCred])).toHaveLength(0);
  });

  it('format 不一致は候補にならない', () => {
    const query = parseDcqlQuery({
      credentials: [{ id: 'q1', format: 'jwt_vc_json' }],
    });
    const matches = evaluateDcql(query, [sdJwtCred, jwtVcCred]);
    expect(matches).toHaveLength(1);
    expect(matches[0]?.credentialId).toBe('urn:cred:2');
  });

  it('values 指定でクレーム値が一致しないと候補にならない', () => {
    const query = parseDcqlQuery({
      credentials: [
        { id: 'q1', format: 'vc+sd-jwt', claims: [{ path: ['age'], values: [18, 19] }] },
      ],
    });
    expect(evaluateDcql(query, [sdJwtCred])).toHaveLength(0);
  });

  it('values 指定でクレーム値が一致すれば候補になる', () => {
    const query = parseDcqlQuery({
      credentials: [
        { id: 'q1', format: 'vc+sd-jwt', claims: [{ path: ['age'], values: [29, 30, 31] }] },
      ],
    });
    expect(evaluateDcql(query, [sdJwtCred])).toHaveLength(1);
  });

  it('存在しない path は候補にならない', () => {
    const query = parseDcqlQuery({
      credentials: [{ id: 'q1', format: 'vc+sd-jwt', claims: [{ path: ['missing'] }] }],
    });
    expect(evaluateDcql(query, [sdJwtCred])).toHaveLength(0);
  });

  it('未対応 format は 8050', () => {
    const query = parseDcqlQuery({ credentials: [{ id: 'q1', format: 'mso_mdoc' }] });
    try {
      evaluateDcql(query, [sdJwtCred]);
      throw new Error('should have thrown');
    } catch (err) {
      expect(err).toBeInstanceOf(VericertsError);
      expect((err as VericertsError).code).toBe(ErrorCodes.FORMAT_NEGOTIATION_FAILED);
    }
  });

  // 検証経路を持たない形式を対応済みとしてネゴシエーションしない。
  it('ldp_vc（Data Integrity VC）の要求は 8050 で拒否する', () => {
    const query = parseDcqlQuery({ credentials: [{ id: 'q1', format: 'ldp_vc' }] });
    expect(() => evaluateDcql(query, [sdJwtCred, jwtVcCred])).toThrow(
      new VericertsError(ErrorCodes.FORMAT_NEGOTIATION_FAILED, {
        context: { format: 'ldp_vc' },
      }),
    );
  });

  it('vc+cose（COSE_Sign1 VC）の要求は 8050 で拒否する', () => {
    const query = parseDcqlQuery({ credentials: [{ id: 'q1', format: 'vc+cose' }] });
    expect(() => evaluateDcql(query, [sdJwtCred, jwtVcCred])).toThrow(
      new VericertsError(ErrorCodes.FORMAT_NEGOTIATION_FAILED, {
        context: { format: 'vc+cose' },
      }),
    );
  });

  it('bbs+（Data Integrity BBS）の要求は 8050 で拒否する', () => {
    const query = parseDcqlQuery({ credentials: [{ id: 'q1', format: 'bbs+' }] });
    expect(() => evaluateDcql(query, [sdJwtCred, jwtVcCred])).toThrow(
      new VericertsError(ErrorCodes.FORMAT_NEGOTIATION_FAILED, {
        context: { format: 'bbs+' },
      }),
    );
  });

  it('複数要件 × 複数クレデンシャルの直積マッチを列挙する', () => {
    const query = parseDcqlQuery({
      credentials: [
        { id: 'q-sd', format: 'vc+sd-jwt' },
        { id: 'q-jwt', format: 'jwt_vc_json' },
      ],
    });
    const matches = evaluateDcql(query, [sdJwtCred, jwtVcCred]);
    expect(matches).toHaveLength(2);
    expect(matches.map((m) => m.queryId).sort()).toEqual(['q-jwt', 'q-sd']);
  });
});
