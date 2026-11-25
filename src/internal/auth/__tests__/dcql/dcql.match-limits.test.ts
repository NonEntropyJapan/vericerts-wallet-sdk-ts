/**
 * DCQL の一致総量（R × H）の上限。
 *
 * 以前は要求側の件数（要件・claims・path・values）だけを縛り、要件 R 件 × 保有 VC H 件ぶんの
 * `CredentialMatch` は H に比例して無制限だった。実時間・RSS ではなく、確保された一致件数・文字列の共有・
 * 例外の種別という決定的な量で pin する。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import {
  type DcqlQuery,
  evaluateDcql,
  findMatchingCredentialIndexes,
  parseDcqlQuery,
  type QueryableCredential,
} from '../../dcql/dcql.js';
import { MAX_DCQL_CREDENTIALS, MAX_DCQL_MATCHES } from '../../dcql/limits.js';
import { matchCredentialsAgainstRequest } from '../../match-credentials/index.js';
import { selectMatchingCredentials } from '../../matcher.js';
import type { PresentationRequest } from '../../request.js';

const CLAIMS_PER_REQUIREMENT = 8;

/** 上限ちょうどの要件数 × `credentialSubject.id` を `CLAIMS_PER_REQUIREMENT` 個要求する DCQL（全 VC が一致する形）。 */
function wideQuery(): DcqlQuery {
  return parseDcqlQuery({
    credentials: Array.from({ length: MAX_DCQL_CREDENTIALS }, (_, i) => ({
      id: `q${i}`,
      format: 'jwt_vc_json',
      claims: Array.from({ length: CLAIMS_PER_REQUIREMENT }, () => ({
        path: ['credentialSubject', 'id'],
      })),
    })),
  });
}

function held(count: number): QueryableCredential[] {
  return Array.from({ length: count }, (_, i) => ({
    id: `urn:uuid:${i}`,
    format: 'jwt_vc_json',
    claims: { credentialSubject: { id: 'did:key:h' } },
  }));
}

/** `MAX_DCQL_MATCHES` を超える保有数（要件 64 件 × この件数 > 上限）。 */
const OVER_CAP_HELD = Math.floor(MAX_DCQL_MATCHES / MAX_DCQL_CREDENTIALS) + 1;

function expectTooManyMatches(fn: () => unknown): void {
  try {
    fn();
  } catch (err) {
    expect(err).toBeInstanceOf(VericertsError);
    expect((err as VericertsError).code).toBe(ErrorCodes.OID4VP_REQUEST_PARSE_FAILED);
    expect((err as VericertsError).context).toMatchObject({ reason: 'too_many_matches' });
    return;
  }
  throw new Error('should have thrown');
}

describe('evaluateDcql: 一致総量の上限', () => {
  it('一致の総数が MAX_DCQL_MATCHES に達する直前までは返し、超える評価は 8030（too_many_matches）', () => {
    const query = wideQuery();
    const atCap = Math.floor(MAX_DCQL_MATCHES / MAX_DCQL_CREDENTIALS);
    expect(evaluateDcql(query, held(atCap))).toHaveLength(atCap * MAX_DCQL_CREDENTIALS);
    expectTooManyMatches(() => evaluateDcql(query, held(OVER_CAP_HELD)));
  });

  it('selectMatchingCredentials も同じ上限で 8030 になる（一部を切り捨てて返さない）', () => {
    expectTooManyMatches(() => selectMatchingCredentials(wideQuery(), held(OVER_CAP_HELD)));
  });

  it('matchedClaims は要件ごとに 1 つの変更不能な配列を全一致で共有する（一致ごとに文字列を確保しない）', () => {
    const matches = evaluateDcql(wideQuery(), held(50));
    const first = matches.filter((m) => m.queryId === 'q0');
    expect(first).toHaveLength(50);
    expect(first[0]?.matchedClaims).toEqual(
      Array.from({ length: CLAIMS_PER_REQUIREMENT }, () => 'credentialSubject.id'),
    );
    expect(new Set(first.map((m) => m.matchedClaims)).size).toBe(1);
    expect(Object.isFrozen(first[0]?.matchedClaims)).toBe(true);
  });
});

describe('findMatchingCredentialIndexes: 一致を確保しない選定', () => {
  it('上限を超える R × H でも 8030 にならず、満たす VC の index を昇順で返す', () => {
    const indexes = findMatchingCredentialIndexes(wideQuery(), held(OVER_CAP_HELD));
    expect(indexes).toHaveLength(OVER_CAP_HELD);
    expect(indexes[0]).toBe(0);
    expect(indexes[OVER_CAP_HELD - 1]).toBe(OVER_CAP_HELD - 1);
  });

  it('いずれの要件も満たさない VC は含めず、format 未対応の要件は evaluateDcql と同じく 8050', () => {
    const query = parseDcqlQuery({
      credentials: [
        { id: 'q', format: 'jwt_vc_json', claims: [{ path: ['credentialSubject', 'name'] }] },
      ],
    });
    const credentials: QueryableCredential[] = [
      { id: 'a', format: 'jwt_vc_json', claims: { credentialSubject: { name: 'x' } } },
      { id: 'b', format: 'jwt_vc_json', claims: { credentialSubject: {} } },
      { id: 'c', format: 'dc+sd-jwt', claims: { credentialSubject: { name: 'x' } } },
    ];
    expect(findMatchingCredentialIndexes(query, credentials)).toEqual([0]);
    expect(() =>
      findMatchingCredentialIndexes(
        { credentials: [{ id: 'q', format: 'mso_mdoc' }] } as unknown as DcqlQuery,
        credentials,
      ),
    ).toThrow(VericertsError);
  });
});

describe('matchCredentialsAgainstRequest: DCQL は一致を確保せずに選定する', () => {
  it('要件 64 × 保有 VC が MAX_DCQL_MATCHES 相当を超えても 8030 にならず全件が合致する', async () => {
    const vcs = Array.from({ length: OVER_CAP_HELD }, (_, i) => ({
      '@context': ['https://www.w3.org/2018/credentials/v1'],
      id: `urn:uuid:${i}`,
      type: ['VerifiableCredential'],
      issuer: 'did:key:z',
      issuanceDate: '2026-01-01T00:00:00Z',
      credentialSubject: { id: 'did:key:h' },
    }));
    const request = { dcqlQuery: wideQuery() } as unknown as PresentationRequest;
    const matched = await matchCredentialsAgainstRequest(request, vcs as never);
    expect(matched).toHaveLength(OVER_CAP_HELD);
  });
});
