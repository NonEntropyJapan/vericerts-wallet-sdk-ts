/**
 * `evaluateDcql`（DCQL 評価）の `Object.prototype` 汚染耐性。
 *
 * `evaluateDcql` は**公開 SDK API** であり、現在は extension が dApp 由来の DCQL を
 * そのまま SDK へ流す。要件・クレデンシャルの任意メンバ（`meta` / `meta.vct_values` /
 * `claims` / `claims[].values` / `credential.vct`）は「条件なし」を own プロパティの**不在**で
 * 表現するため、鎖読みだと汚染値が条件として採用され評価結果が変わる。
 *
 * - `claims` / `values` / `meta` / `vct_values`: **制約を持たない要件**（その format の VC なら
 *   何でも合致する要件）に継承値が条件として使われ、本来マッチすべき候補が落ちる。
 * - `vct`: `vct` を持たないクレデンシャルに継承値が生え、`vct_values` 指定の要件へ**誤って
 *   合致する**（fail-open。攻撃者が DCQL と汚染の両方を握れば意図しない VC が提示候補になる）。
 *
 * テストは**キーを 1 つずつ単独で汚染する**（mutation check が「この 1 行を戻すとこのテストが
 * 落ちる」という形で成立するように）。`evaluateDcql` は同期関数なので
 * `withPollutedPrototype` / `withPollutedPrototypeAccessor`（同期版）を使う。
 * アサーションは汚染を戻した後で行う（汚染下だとアサーション自体が鎖読みで曇るため）。
 */

import { describe, expect, it } from 'bun:test';
import {
  withPollutedPrototype,
  withPollutedPrototypeAccessor,
} from '../../../__tests__/prototype-pollution.fixtures.js';
import {
  type CredentialMatch,
  type DcqlQuery,
  evaluateDcql,
  type QueryableCredential,
} from '../../dcql/dcql.js';

/** SD-JWT VC（`vct` あり）。 */
const SD_JWT_CREDENTIAL: QueryableCredential = {
  id: 'cred-pid',
  format: 'dc+sd-jwt',
  vct: 'https://example.com/pid',
  claims: { given_name: 'Alice' },
};

/** `vct` クレームを持たない SD-JWT VC（`matcher.ts` は `vct` を条件付き展開で落とす）。 */
const SD_JWT_WITHOUT_VCT: QueryableCredential = {
  id: 'cred-no-vct',
  format: 'dc+sd-jwt',
  claims: { given_name: 'Alice' },
};

/** JWT-VC（`vct` を持たない）。 */
const JWT_VC_CREDENTIAL: QueryableCredential = {
  id: 'cred-jwt',
  format: 'jwt_vc_json',
  claims: { credentialSubject: { name: 'Alice' } },
};

/** 汚染キー 1 つと、そのキーを own プロパティとして持たない評価入力の組。 */
interface EvaluateCase {
  /** 単独で汚染するキー。 */
  readonly key: string;
  /** 汚染値。 */
  readonly value: unknown;
  /** 鎖読みだと何が起きるか（テスト名に出す）。 */
  readonly harm: string;
  /** `key` を own プロパティとして持たない要件を含むクエリ。 */
  readonly query: DcqlQuery;
  /** 評価対象クレデンシャル。 */
  readonly credentials: readonly QueryableCredential[];
  /** 汚染の有無に関わらずマッチすべきクレデンシャル ID。 */
  readonly expectedCredentialIds: readonly string[];
}

const CASES: readonly EvaluateCase[] = [
  {
    key: 'claims',
    value: [{ path: ['attacker'] }],
    harm: 'クレーム制約を持たない要件が汚染クレームを条件に使う',
    query: { credentials: [{ id: 'q1', format: 'jwt_vc_json' }] },
    credentials: [JWT_VC_CREDENTIAL],
    expectedCredentialIds: ['cred-jwt'],
  },
  {
    key: 'values',
    value: ['attacker-value'],
    harm: '値制約を持たないクレームが汚染値を条件に使う',
    query: {
      credentials: [
        { id: 'q1', format: 'jwt_vc_json', claims: [{ path: ['credentialSubject', 'name'] }] },
      ],
    },
    credentials: [JWT_VC_CREDENTIAL],
    expectedCredentialIds: ['cred-jwt'],
  },
  {
    key: 'meta',
    value: { vct_values: ['https://attacker.example/vct'] },
    harm: 'meta を持たない要件が汚染 vct 制約を条件に使う',
    query: { credentials: [{ id: 'q1', format: 'dc+sd-jwt' }] },
    credentials: [SD_JWT_CREDENTIAL],
    expectedCredentialIds: ['cred-pid'],
  },
  {
    key: 'vct_values',
    value: ['https://attacker.example/vct'],
    harm: 'vct_values を持たない meta が汚染値を条件に使う',
    query: { credentials: [{ id: 'q1', format: 'dc+sd-jwt', meta: {} }] },
    credentials: [SD_JWT_CREDENTIAL],
    expectedCredentialIds: ['cred-pid'],
  },
  {
    key: 'vct',
    value: 'https://attacker.example/vct',
    harm: 'vct を持たないクレデンシャルが vct_values 指定の要件へ誤って合致する',
    query: {
      credentials: [
        {
          id: 'q1',
          format: 'dc+sd-jwt',
          meta: { vct_values: ['https://attacker.example/vct'] },
        },
      ],
    },
    credentials: [SD_JWT_WITHOUT_VCT],
    expectedCredentialIds: [],
  },
];

const matchedIds = (matches: readonly CredentialMatch[]): string[] =>
  matches.map((match) => match.credentialId);

describe('evaluateDcql: Object.prototype 汚染耐性', () => {
  for (const testCase of CASES) {
    const title = `${testCase.key} の汚染で${testCase.harm}`;

    it(`${title}（データ汚染）`, () => {
      const matches = withPollutedPrototype({ [testCase.key]: testCase.value }, () =>
        evaluateDcql(testCase.query, testCase.credentials),
      );
      expect(matchedIds(matches)).toEqual([...testCase.expectedCredentialIds]);
    });

    it(`${title}（アクセサ汚染）`, () => {
      const matches = withPollutedPrototypeAccessor({ [testCase.key]: () => testCase.value }, () =>
        evaluateDcql(testCase.query, testCase.credentials),
      );
      expect(matchedIds(matches)).toEqual([...testCase.expectedCredentialIds]);
    });
  }
});

/**
 * 汚染下でも、明示された条件はこれまでどおり効くこと（own 化が「常に条件なし」へ倒れる退行に
 * なっていないことの確認）。
 */
describe('evaluateDcql: 汚染下でも明示された条件は効く', () => {
  const query: DcqlQuery = {
    credentials: [
      {
        id: 'q1',
        format: 'dc+sd-jwt',
        meta: { vct_values: ['https://example.com/pid'] },
        claims: [{ path: ['given_name'], values: ['Alice'] }],
      },
    ],
  };

  const ALL_POLLUTED: Record<string, unknown> = {
    claims: [{ path: ['attacker'] }],
    values: ['attacker-value'],
    meta: { vct_values: ['https://attacker.example/vct'] },
    vct_values: ['https://attacker.example/vct'],
    vct: 'https://attacker.example/vct',
  };
  const ALL_POLLUTED_GETTERS = Object.fromEntries(
    Object.entries(ALL_POLLUTED).map(([key, value]) => [key, () => value]),
  );

  type PollutionRunner = (fn: () => CredentialMatch[]) => CredentialMatch[];
  const FORMS: readonly (readonly [string, PollutionRunner])[] = [
    ['データ汚染', (fn) => withPollutedPrototype(ALL_POLLUTED, fn)],
    ['アクセサ汚染', (fn) => withPollutedPrototypeAccessor(ALL_POLLUTED_GETTERS, fn)],
  ];

  for (const [form, run] of FORMS) {
    it(`vct_values / values を満たすクレデンシャルだけがマッチする（${form}）`, () => {
      const matches = run(() =>
        evaluateDcql(query, [SD_JWT_CREDENTIAL, SD_JWT_WITHOUT_VCT, JWT_VC_CREDENTIAL]),
      );
      expect(matchedIds(matches)).toEqual(['cred-pid']);
      expect(matches[0]?.matchedClaims).toEqual(['given_name']);
    });

    it(`値が一致しないクレデンシャルはマッチしない（${form}）`, () => {
      const other: QueryableCredential = {
        id: 'cred-other',
        format: 'dc+sd-jwt',
        vct: 'https://example.com/pid',
        claims: { given_name: 'Bob' },
      };
      const matches = run(() => evaluateDcql(query, [other]));
      expect(matches).toEqual([]);
    });
  }
});

describe('evaluateDcql の必須メンバも own 限定で読む', () => {
  /** `format` を own に持たない要件（型としては必須だが、実体は RP が組む JSON）。 */
  const FORMATLESS_QUERY = {
    credentials: [{ id: 'q-1' }],
  } as unknown as DcqlQuery;

  it('format を own に持たない要件は 8050 で落ちる（evaluateDcql のゲート）', () => {
    // ここが見ているのは `evaluateDcql` 冒頭の format ゲートであって
    // `evaluateCredentialRequirement` の `!==` 比較ではない。汚染が無ければ鎖読みでも
    // `undefined` になり 8050 が出るため、**own 読みの回帰検知にはならない**（下の 2 件が担う）。
    const formatless = { id: 'cred-x', claims: {} } as unknown as QueryableCredential;
    expect(() => evaluateDcql(FORMATLESS_QUERY, [formatless])).toThrow();
  });

  it('汚染された format でクレデンシャル側の format 不在が一致扱いにならない', () => {
    // `evaluateCredentialRequirement` の `requiredFormat !== ownProperty(credential, 'format')`
    // を実際に通す唯一の形: 要件は own に対応 format を持ち（= 8050 ゲートを通る）、
    // クレデンシャルは own に `format` を持たない。鎖読みだと汚染値が生えて一致し、
    // **format の違う VC が提示候補になる**（fail-open）。
    const query = {
      credentials: [{ id: 'q-1', format: 'dc+sd-jwt' }],
    } as unknown as DcqlQuery;
    const formatless = {
      id: 'cred-x',
      claims: { given_name: 'Alice' },
    } as unknown as QueryableCredential;

    const matches = withPollutedPrototype({ format: 'dc+sd-jwt' }, () =>
      evaluateDcql(query, [formatless]),
    );
    expect(matches).toEqual([]);
  });

  it('汚染された format で未対応 format の要件が対応扱いにならない', () => {
    // `Object.prototype.format` が対応 format なら、鎖読みでは 8050 を投げずに評価へ進んでしまう。
    expect(() =>
      withPollutedPrototype({ format: 'dc+sd-jwt' }, () =>
        evaluateDcql(FORMATLESS_QUERY, [SD_JWT_CREDENTIAL]),
      ),
    ).toThrow();
  });

  it('own アクセサの format を 2 度読まない（ゲートと突き合わせで同じ値を使う）', () => {
    // own のアクセサプロパティは読むたびに別の値を返せる。`format` を 2 度読むと、
    // 「対応 format 検査（8050 ゲート）には対応 format を、クレデンシャルとの突き合わせには
    // 別の値を」返す要件を作れてしまう。1 回読んだ値を引き回すことで塞ぐ。
    let reads = 0;
    const requirement = { id: 'q-1' };
    Object.defineProperty(requirement, 'format', {
      enumerable: true,
      configurable: true,
      get: () => {
        reads += 1;
        return reads === 1 ? 'dc+sd-jwt' : 'mso_mdoc';
      },
    });
    const query = { credentials: [requirement] } as unknown as DcqlQuery;

    const matches = evaluateDcql(query, [SD_JWT_CREDENTIAL]);

    expect(reads).toBe(1);
    expect(matchedIds(matches)).toEqual(['cred-pid']);
  });

  it('format が own に無い要件の 8050 は context に format キーを載せない', () => {
    // 載せると「8050 が拒否した値」を指さない `format: undefined` がログに残る。
    const formatless = { id: 'cred-x', claims: {} } as unknown as QueryableCredential;
    try {
      evaluateDcql(FORMATLESS_QUERY, [formatless]);
      throw new Error('8050 が投げられませんでした');
    } catch (err) {
      // `toEqual` は値 `undefined` のキーを無視するので、キーの有無で確かめる。
      const context = (err as { context?: Record<string, unknown> }).context ?? {};
      expect(Object.hasOwn(context, 'format')).toBe(false);
    }
  });

  it('汚染された credentials をクエリの要件として評価しない', () => {
    const matches = withPollutedPrototype(
      { credentials: [{ id: 'attacker', format: 'dc+sd-jwt' }] },
      () => evaluateDcql({} as unknown as DcqlQuery, [SD_JWT_CREDENTIAL]),
    );
    expect(matches).toEqual([]);
  });
});
