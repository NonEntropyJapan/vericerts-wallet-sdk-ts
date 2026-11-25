/**
 * DCQL クエリの件数上限。
 *
 * 要求 R 件 × 保有 VC H 件ぶんの `CredentialMatch` を評価が確保するため、1 MiB の `dcql_query` に
 * 同形の要求を数万件並べるとメモリが枯渇した。実時間・RSS ではなく決定的なカウンタ
 * （要素の読み出し回数・確保された一致件数・例外の種別）で pin する。
 */

import { describe, expect, it } from 'bun:test';
import type { VerifiableCredential } from '../../../credential/index.js';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import { type DcqlQuery, evaluateDcql, parseDcqlQuery } from '../../dcql/dcql.js';
import {
  MAX_DCQL_ARRAY_LENGTH,
  MAX_DCQL_CLAIMS_PER_CREDENTIAL,
  MAX_DCQL_CREDENTIALS,
  MAX_DCQL_PATH_LENGTH,
} from '../../dcql/limits.js';
import { selectMatchingCredentials, toQueryableFromVc } from '../../matcher.js';

/** 添字読み出しを数える配列（`Array.isArray` は `true`）。要素を 1 件も読まずに拒否できるかの検証用。 */
function countingArray(length: number, make: (i: number) => unknown) {
  const counter = { reads: 0 };
  const proxy = new Proxy(
    Array.from({ length }, (_, i) => make(i)),
    {
      get(target, key, receiver) {
        if (typeof key === 'string' && /^\d+$/.test(key)) {
          counter.reads += 1;
        }
        return Reflect.get(target, key, receiver);
      },
    },
  );
  return { array: proxy, counter };
}

function expectTooLarge(fn: () => unknown): void {
  try {
    fn();
  } catch (err) {
    expect(err).toBeInstanceOf(VericertsError);
    expect((err as VericertsError).code).toBe(ErrorCodes.OID4VP_REQUEST_PARSE_FAILED);
    expect((err as VericertsError).context).toMatchObject({ reason: 'dcql_too_large' });
    return;
  }
  throw new Error('should have thrown');
}

const requirement = (i: number) => ({ id: `q${i}`, format: 'jwt_vc_json' });

describe('parseDcqlQuery: 件数上限', () => {
  it('credentials は上限ちょうどまで受理し、超えると 8030（dcql_too_large）', () => {
    const at = Array.from({ length: MAX_DCQL_CREDENTIALS }, (_, i) => requirement(i));
    expect(parseDcqlQuery({ credentials: at }).credentials).toHaveLength(MAX_DCQL_CREDENTIALS);
    expectTooLarge(() => parseDcqlQuery({ credentials: [...at, requirement(at.length)] }));
  });

  it('1 MiB 級の要求 28,000 件は要素を 1 件も読まずに拒否する（修正前は全件パースして確保）', () => {
    const { array, counter } = countingArray(28_000, requirement);
    expectTooLarge(() =>
      parseDcqlQuery({ credentials: array } as unknown as Record<string, unknown>),
    );
    expect(counter.reads).toBe(0);
  });

  it('claims は上限ちょうどまで受理し、超えると要素を読まずに 8030', () => {
    const claim = { path: ['credentialSubject', 'name'] };
    const at = Array.from({ length: MAX_DCQL_CLAIMS_PER_CREDENTIAL }, () => claim);
    const parse = (claims: unknown) =>
      parseDcqlQuery({ credentials: [{ id: 'q', format: 'jwt_vc_json', claims }] });
    expect(parse(at).credentials[0]?.claims).toHaveLength(MAX_DCQL_CLAIMS_PER_CREDENTIAL);
    const { array, counter } = countingArray(MAX_DCQL_CLAIMS_PER_CREDENTIAL + 1, () => claim);
    expectTooLarge(() => parse(array));
    expect(counter.reads).toBe(0);
  });

  it('path は上限ちょうどまで受理し、超えると 8030', () => {
    const parse = (path: string[]) =>
      parseDcqlQuery({ credentials: [{ id: 'q', format: 'jwt_vc_json', claims: [{ path }] }] });
    expect(parse(Array.from({ length: MAX_DCQL_PATH_LENGTH }, () => 'a'))).toBeDefined();
    expectTooLarge(() => parse(Array.from({ length: MAX_DCQL_PATH_LENGTH + 1 }, () => 'a')));
  });

  it('values / vct_values は上限ちょうどまで受理し、超えると 8030', () => {
    const items = (n: number) => Array.from({ length: n }, (_, i) => `v${i}`);
    const parseValues = (values: string[]) =>
      parseDcqlQuery({
        credentials: [{ id: 'q', format: 'jwt_vc_json', claims: [{ path: ['a'], values }] }],
      });
    const parseVct = (vct_values: string[]) =>
      parseDcqlQuery({ credentials: [{ id: 'q', format: 'dc+sd-jwt', meta: { vct_values } }] });
    expect(parseValues(items(MAX_DCQL_ARRAY_LENGTH))).toBeDefined();
    expect(parseVct(items(MAX_DCQL_ARRAY_LENGTH))).toBeDefined();
    expectTooLarge(() => parseValues(items(MAX_DCQL_ARRAY_LENGTH + 1)));
    expectTooLarge(() => parseVct(items(MAX_DCQL_ARRAY_LENGTH + 1)));
  });
});

describe('evaluateDcql / selectMatchingCredentials: 手組みのクエリも要件数で拒否', () => {
  const held: VerifiableCredential[] = Array.from(
    { length: 5 },
    (_, i) =>
      ({
        '@context': ['https://www.w3.org/2018/credentials/v1'],
        id: `urn:uuid:${i}`,
        type: ['VerifiableCredential'],
        issuer: 'did:key:z',
        issuanceDate: '2026-01-01T00:00:00Z',
        credentialSubject: { id: 'did:key:h', name: 'n' },
      }) as unknown as VerifiableCredential,
  );
  const queryables = held.map((vc) => toQueryableFromVc(vc));

  it('要件が上限を超えると、要件を 1 件も評価せず（一致を確保せず）8030', () => {
    const { array, counter } = countingArray(28_000, requirement);
    const query = { credentials: array } as unknown as DcqlQuery;
    expectTooLarge(() => evaluateDcql(query, queryables));
    expectTooLarge(() => selectMatchingCredentials(query, queryables));
    expect(counter.reads).toBe(0);
  });

  it('上限ちょうどの要件数は評価でき、一致件数は 要件数 × 保有数 で頭打ちになる', () => {
    const query: DcqlQuery = {
      credentials: Array.from({ length: MAX_DCQL_CREDENTIALS }, (_, i) => requirement(i)),
    };
    const { matches, matchedIndexes } = selectMatchingCredentials(query, queryables);
    expect(matches).toHaveLength(MAX_DCQL_CREDENTIALS * held.length);
    expect(matchedIndexes).toEqual([0, 1, 2, 3, 4]);
  });
});
