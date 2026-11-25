/**
 * `parseDcqlQuery`（DCQL クエリのパース）の `Object.prototype` 汚染耐性。
 *
 * `parseDcqlQuery`（`dcql.ts`）は**公開 SDK API**（`src/exports/auth.ts` からエクスポート）で
 * あり、SDK 内部の呼び出し元（`request.ts` の `decodeJsonParam` / `parseJarRequest`）のように
 * `raw` が `parseJsonWithoutPrototype` 由来の null プロトタイプであるとは限らない。SDK 利用者は
 * `JSON.parse` の戻り値や手組みのオブジェクトリテラル（`Object.prototype` を継承）を直接渡し得る。
 *
 * 鎖読みだと、対象キーを**持たない**正当な入力でも汚染値が採用され、それぞれ別の実害になる。
 *
 * - `credentials`: トップレベルに `credentials` を持たないクエリが構造検証を通過する
 *   （必須フィールド欠落チェックそのものが無効化される）。
 * - `id` / `format`: これらを持たないクレデンシャル要件が構造検証を通過する。
 * - `path`: `path` を持たないクレーム条件が「空配列拒否」の必須検査を素通りする。
 * - `values` / `vct_values`: 任意フィールドを持たない要件・クレームに、攻撃者が選んだ値が
 *   own プロパティとして repack される（必須検査は通らないが、下流の評価・マッチングが
 *   汚染値を「指定された」条件として扱う）。
 *
 * テストは**キーを 1 つずつ単独で汚染する**（mutation check が「この 1 行を戻すとこのテストが
 * 落ちる」という形で成立するように）。`parseDcqlQuery` は同期関数なので
 * `withPollutedPrototype` / `withPollutedPrototypeAccessor`（同期版）を使う。
 */

import { describe, expect, it } from 'bun:test';
import {
  withPollutedPrototype,
  withPollutedPrototypeAccessor,
} from '../../../__tests__/prototype-pollution.fixtures.js';
import { ErrorCodes, type VericertsError } from '../../../errors.js';
import { type DcqlQuery, parseDcqlQuery } from '../../dcql/dcql.js';

/** 汚染キー 1 つと、そのキーを own プロパティとして持たないクエリ（または部分構造）の組。 */
interface RejectCase {
  /** 単独で汚染するキー。 */
  readonly key: string;
  /** 汚染値。 */
  readonly value: unknown;
  /** `key` を own プロパティとして持たないクエリ。 */
  readonly query: Record<string, unknown>;
  /** 鎖読みだと何が起きるか（テスト名に出す）。 */
  readonly harm: string;
}

const REJECT_CASES: readonly RejectCase[] = [
  {
    key: 'credentials',
    value: [{ id: 'attacker', format: 'jwt_vc_json' }],
    query: {},
    harm: 'credentials 欠落が検知されない',
  },
  {
    key: 'id',
    value: 'attacker-id',
    query: { credentials: [{ format: 'jwt_vc_json' }] },
    harm: 'credential.id 欠落が検知されない',
  },
  {
    key: 'format',
    value: 'jwt_vc_json',
    query: { credentials: [{ id: 'x' }] },
    harm: 'credential.format 欠落が検知されない',
  },
  {
    key: 'path',
    value: ['attacker'],
    query: { credentials: [{ id: 'x', format: 'jwt_vc_json', claims: [{}] }] },
    harm: 'claim.path 欠落が検知されない',
  },
];

describe('parseDcqlQuery: Object.prototype 汚染耐性', () => {
  for (const testCase of REJECT_CASES) {
    const title = `${testCase.key} の汚染で${testCase.harm}`;

    it(`${title}（データ汚染）`, () => {
      withPollutedPrototype({ [testCase.key]: testCase.value }, () => {
        try {
          parseDcqlQuery(testCase.query);
          throw new Error('should throw');
        } catch (e) {
          expect((e as VericertsError).code).toBe(ErrorCodes.OID4VP_REQUEST_PARSE_FAILED);
        }
      });
    });

    it(`${title}（アクセサ汚染）`, () => {
      withPollutedPrototypeAccessor({ [testCase.key]: () => testCase.value }, () => {
        try {
          parseDcqlQuery(testCase.query);
          throw new Error('should throw');
        } catch (e) {
          expect((e as VericertsError).code).toBe(ErrorCodes.OID4VP_REQUEST_PARSE_FAILED);
        }
      });
    });
  }
});

describe('parseDcqlQuery: 任意フィールド欠落時に汚染値を採用しない', () => {
  // アサーションは `Object.hasOwn` で行う（`toBeUndefined()` は不可）。アサーション自体が
  // `withPollutedPrototype` の中（＝汚染が有効なまま）で実行されるため、返り値の
  // `claim.values` / `meta.vct_values` をドットアクセス（プロトタイプ鎖読み）で読むと、
  // 修正の有無によらず常に汚染値が見えてしまい退行を検知できない（own 化されていなくても
  // 素の `{}` はどのみち `Object.prototype` を継承するため）。ここで検証すべきは
  // 「パース結果が汚染値を **own プロパティとして採用していない** こと」であり、
  // `Object.hasOwn` はプロトタイプ鎖の状態に関わらずその判定ができる。
  it('claim.values 欠落時に汚染値を own プロパティとして採用しない（データ汚染）', () => {
    withPollutedPrototype({ values: ['attacker-value'] }, () => {
      const query = parseDcqlQuery({
        credentials: [{ id: 'x', format: 'jwt_vc_json', claims: [{ path: ['a'] }] }],
      });
      const claim = query.credentials[0]?.claims?.[0] ?? {};
      expect(Object.hasOwn(claim, 'values')).toBe(false);
    });
  });

  it('claim.values 欠落時に汚染値を own プロパティとして採用しない（アクセサ汚染）', () => {
    withPollutedPrototypeAccessor({ values: () => ['attacker-value'] }, () => {
      const query = parseDcqlQuery({
        credentials: [{ id: 'x', format: 'jwt_vc_json', claims: [{ path: ['a'] }] }],
      });
      const claim = query.credentials[0]?.claims?.[0] ?? {};
      expect(Object.hasOwn(claim, 'values')).toBe(false);
    });
  });

  it('meta.vct_values 欠落時に汚染値を own プロパティとして採用しない（データ汚染）', () => {
    withPollutedPrototype({ vct_values: ['https://attacker.example/vct'] }, () => {
      const query = parseDcqlQuery({
        credentials: [{ id: 'x', format: 'vc+sd-jwt', meta: {} }],
      });
      const meta = query.credentials[0]?.meta ?? {};
      expect(Object.hasOwn(meta, 'vct_values')).toBe(false);
    });
  });

  it('meta.vct_values 欠落時に汚染値を own プロパティとして採用しない（アクセサ汚染）', () => {
    withPollutedPrototypeAccessor({ vct_values: () => ['https://attacker.example/vct'] }, () => {
      const query = parseDcqlQuery({
        credentials: [{ id: 'x', format: 'vc+sd-jwt', meta: {} }],
      });
      const meta = query.credentials[0]?.meta ?? {};
      expect(Object.hasOwn(meta, 'vct_values')).toBe(false);
    });
  });
});

/**
 * 汚染下でも正当なクエリはそのまま採用されること（非退行）。
 *
 * own 化が「常に 8030 へ倒れるだけ」の退行になっていないことを示すため、全キーを汚染した状態で
 * 完全な正当クエリがこれまでどおりパースされ、かつネストした各値（`credential.id` /
 * `credential.format` / `meta.vct_values` / `claim.path` / `claim.values`）が汚染値ではなく
 * 呼び出し側が渡した値で、**own プロパティとして** repack されていることを確認する。
 */
describe('parseDcqlQuery: 汚染下でも正当なクエリをそのまま採用する', () => {
  const honestQuery = (): Record<string, unknown> => ({
    credentials: [
      {
        id: 'pid',
        format: 'vc+sd-jwt',
        meta: { vct_values: ['https://example.com/pid'] },
        claims: [{ path: ['given_name'] }, { path: ['age'], values: [18, 19, 20] }],
      },
    ],
  });

  const ALL_POLLUTED: Record<string, unknown> = {
    credentials: [{ id: 'attacker', format: 'jwt_vc_json' }],
    id: 'attacker-id',
    format: 'jwt_vc_json',
    path: ['attacker'],
    values: ['attacker-value'],
    vct_values: ['https://attacker.example/vct'],
  };
  const ALL_POLLUTED_GETTERS = Object.fromEntries(
    Object.entries(ALL_POLLUTED).map(([key, value]) => [key, () => value]),
  );

  type PollutionRunner = (fn: () => DcqlQuery) => DcqlQuery;
  const FORMS: readonly (readonly [string, PollutionRunner])[] = [
    ['データ汚染', (fn) => withPollutedPrototype(ALL_POLLUTED, fn)],
    ['アクセサ汚染', (fn) => withPollutedPrototypeAccessor(ALL_POLLUTED_GETTERS, fn)],
  ];

  for (const [form, run] of FORMS) {
    it(`正当なクエリは呼び出し側が渡した値どおりにパースされる（${form}）`, () => {
      const query = run(() => parseDcqlQuery(honestQuery()));

      const cred = query.credentials[0];
      expect(cred?.id).toBe('pid');
      expect(cred?.format).toBe('vc+sd-jwt');
      expect(cred?.meta?.vct_values).toEqual(['https://example.com/pid']);
      expect(cred?.claims?.[0]?.path).toEqual(['given_name']);
      expect(cred?.claims?.[1]?.values).toEqual([18, 19, 20]);

      expect(Object.hasOwn(query, 'credentials')).toBe(true);
      expect(Object.hasOwn(cred as object, 'id')).toBe(true);
      expect(Object.hasOwn(cred as object, 'format')).toBe(true);
    });
  }
});
