/**
 * `parseGrants`（Credential Offer の `grants` 解析）の `Object.prototype` 汚染耐性。
 *
 * `parse-json.ts` の方針は「パース境界（`parseJsonWithoutPrototype`）で null プロトタイプ化し、
 * **読み取り時点の own 限定読み（`ownProperty`）も多層防御として維持する**」である。兄弟パーサ
 * （`oid4vci-par-response.ts` / `oid4vci-credential-response.ts` / `oid4vci-as-metadata.ts`）は
 * `ownProperty` で読んでいるが、Offer の grant 解析だけが鎖読み（`grant['pre-authorized_code']` /
 * `grant.tx_code` 等）のままだった。
 *
 * `parseGrants` は **export された関数**であり、JSON 文字列を経由しない呼び出し
 * （プレーンなオブジェクトリテラル = `Object.prototype` を継承する値）を受け取り得る。この経路では
 * パース境界の null プロトタイプ化が効かず、鎖読みがそのまま実害になる。
 *
 * - `grants` 直下（`urn:...:pre-authorized_code` / `authorization_code`）:
 *   **Offer が告知していない grant が生える**。呼び出し側は `Object.hasOwn` で grant の有無を
 *   判定するため（`oid4vci-offer-grants.ts` の設計コメント参照）、攻撃者の code で Token Request
 *   に進む / 攻撃者の AS へ認可を向ける経路が開く。
 * - `pre-authorized_code`: 必須フィールドの欠落チェックが素通りし、**攻撃者の code が採用される**。
 * - `tx_code` / `length` / `input_mode`: Offer が省略した PIN 要件が生える、または PIN 要件の
 *   欠損検知が素通りし攻撃者が選んだ桁数・入力モードが採用される。
 * - `issuer_state` / `authorization_server`: PAR へ載る値が
 *   汚染され、**認可要求が攻撃者の AS / セッションへ紐付く**。
 *
 * 型ガード（`typeof value !== 'object'` / `isNonEmptyString`）は汚染値が正しい型であれば素通り
 * するため防げない。`parseGrants` は同期関数なので `withPollutedPrototype` /
 * `withPollutedPrototypeAccessor`（同期版）を使う。
 *
 * 汚染の影響が `expect` 等のテスト基盤へ波及しないよう、**汚染下では `parseGrants` の呼び出し
 * だけを行い**、結果（戻り値 / 例外）を持ち出してから汚染解除後に検証する。
 */

import { describe, expect, it } from 'bun:test';
import {
  withPollutedPrototype,
  withPollutedPrototypeAccessor,
} from '../../../__tests__/prototype-pollution.fixtures.js';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import {
  AUTHORIZATION_CODE_GRANT,
  type CredentialGrants,
  PRE_AUTHORIZED_CODE_GRANT,
  parseGrants,
} from '../../oid4vci/offer/oid4vci-offer-grants.js';

/** 汚染下で `parseGrants` を呼んだ結果（戻り値 / 例外）を汚染解除後まで持ち出すための型。 */
type ParseOutcome =
  | { readonly ok: true; readonly grants: CredentialGrants | undefined }
  | { readonly ok: false; readonly error: unknown };

/** `Object.prototype` を汚染した状態で同期処理を走らせる関数（データ汚染 / アクセサ汚染）。 */
type PollutionRunner = (fn: () => ParseOutcome) => ParseOutcome;

/** `props` を getter 形式（呼ばれるたびに値を返す）へ変換する。 */
function toGetters(props: Readonly<Record<string, unknown>>): Record<string, () => unknown> {
  return Object.fromEntries(Object.entries(props).map(([key, value]) => [key, () => value]));
}

/** 汚染下で `parseGrants(value)` を 1 回だけ呼び、結果を捕捉して返す。 */
function parseUnderPollution(run: PollutionRunner, value: unknown): ParseOutcome {
  return run(() => {
    try {
      return { ok: true, grants: parseGrants(value) };
    } catch (error) {
      return { ok: false, error };
    }
  });
}

/** `parseGrants` が `OFFER_URI_PARSE_FAILED`（3003）で拒否したことを検証する。 */
function expectRejected(outcome: ParseOutcome): void {
  if (outcome.ok) {
    throw new Error('parseGrants は OFFER_URI_PARSE_FAILED で拒否するはずが値を返した');
  }
  expect(outcome.error).toBeInstanceOf(VericertsError);
  expect((outcome.error as VericertsError).code).toBe(ErrorCodes.OFFER_URI_PARSE_FAILED);
}

/** `parseGrants` が受理したことを検証し、正規化済み grants を返す。 */
function expectAccepted(outcome: ParseOutcome): CredentialGrants {
  if (!outcome.ok) {
    throw outcome.error;
  }
  if (outcome.grants === undefined) {
    throw new Error('parseGrants は grants を返すはずが undefined を返した');
  }
  return outcome.grants;
}

/** 汚染キーと、そのキーを own プロパティとして持たない grants の組。 */
interface OwnReadCase {
  /** 単独で汚染するキー（およびその汚染値）。 */
  readonly pollution: Readonly<Record<string, unknown>>;
  /** 汚染キーを own プロパティとして持たない `grants`（`JSON.parse` を経由しない生リテラル）。 */
  readonly grants: Record<string, unknown>;
  /** 鎖読みだと何が起きるか（テスト名に出す）。 */
  readonly harm: string;
  /** own 限定読みでの期待結果。 */
  readonly verify: (outcome: ParseOutcome) => void;
}

const OWN_READ_CASES: readonly OwnReadCase[] = [
  {
    pollution: { [PRE_AUTHORIZED_CODE_GRANT]: { 'pre-authorized_code': 'attacker-code' } },
    grants: {},
    harm: '告知されていない pre-authorized_code grant が生える',
    verify: (outcome) => {
      const grants = expectAccepted(outcome);
      expect(Object.hasOwn(grants, PRE_AUTHORIZED_CODE_GRANT)).toBe(false);
    },
  },
  {
    pollution: { [AUTHORIZATION_CODE_GRANT]: { issuer_state: 'attacker-state' } },
    grants: {},
    harm: '告知されていない authorization_code grant が生える',
    verify: (outcome) => {
      const grants = expectAccepted(outcome);
      expect(Object.hasOwn(grants, AUTHORIZATION_CODE_GRANT)).toBe(false);
    },
  },
  {
    pollution: { 'pre-authorized_code': 'attacker-code' },
    grants: { [PRE_AUTHORIZED_CODE_GRANT]: {} },
    harm: 'pre-authorized_code 欠落が検知されず攻撃者の code が採用される',
    verify: expectRejected,
  },
  {
    pollution: { tx_code: { length: 4, input_mode: 'numeric' } },
    grants: { [PRE_AUTHORIZED_CODE_GRANT]: { 'pre-authorized_code': 'code-1' } },
    harm: 'Offer が省略した PIN 要件（tx_code）が生える',
    verify: (outcome) => {
      const grant = expectAccepted(outcome)[PRE_AUTHORIZED_CODE_GRANT];
      expect(grant?.['pre-authorized_code']).toBe('code-1');
      expect(grant?.tx_code).toBeUndefined();
      expect(Object.hasOwn(grant as object, 'tx_code')).toBe(false);
    },
  },
  {
    pollution: { length: 4, input_mode: 'text', description: 'attacker description' },
    grants: {
      [PRE_AUTHORIZED_CODE_GRANT]: { 'pre-authorized_code': 'code-1', tx_code: {} },
    },
    harm: 'tx_code.length / input_mode / description の省略が埋められ攻撃者が選んだ PIN 要件が採用される',
    verify: (outcome) => {
      // メンバはすべて任意。省略は own 限定読みで「未告知」として扱い、既定値（numeric）だけが入る。
      const txCode = expectAccepted(outcome)[PRE_AUTHORIZED_CODE_GRANT]?.tx_code;
      expect(txCode).toEqual({ input_mode: 'numeric' });
      expect(Object.hasOwn(txCode as object, 'length')).toBe(false);
      expect(Object.hasOwn(txCode as object, 'description')).toBe(false);
    },
  },
  {
    pollution: {
      issuer_state: 'attacker-state',
      authorization_server: 'https://attacker.example',
    },
    grants: { [AUTHORIZATION_CODE_GRANT]: {} },
    harm: '偽の issuer_state / authorization_server が PAR へ載る',
    verify: (outcome) => {
      const grant = expectAccepted(outcome)[AUTHORIZATION_CODE_GRANT];
      expect(grant).toEqual({});
      expect(Object.hasOwn(grant as object, 'issuer_state')).toBe(false);
      expect(Object.hasOwn(grant as object, 'authorization_server')).toBe(false);
    },
  },
];

describe('parseGrants: Object.prototype 汚染耐性', () => {
  const FORMS: readonly (readonly [string, (props: Record<string, unknown>) => PollutionRunner])[] =
    [
      ['データ汚染', (props) => (fn) => withPollutedPrototype(props, fn)],
      ['アクセサ汚染', (props) => (fn) => withPollutedPrototypeAccessor(toGetters(props), fn)],
    ];

  for (const testCase of OWN_READ_CASES) {
    const keys = Object.keys(testCase.pollution).join(' / ');
    for (const [form, toRunner] of FORMS) {
      it(`${keys} の汚染で${testCase.harm}（${form}）`, () => {
        testCase.verify(parseUnderPollution(toRunner({ ...testCase.pollution }), testCase.grants));
      });
    }
  }
});

/**
 * 汚染下でも Issuer が**実際に告知した**正当な grants はそのまま採用されること（非退行）。
 *
 * own 限定読みが「常に 3003 へ倒れる」「常にキーを落とす」だけの退行になっていないことを示すため、
 * 関係するキーを一括で汚染した状態で、全キーを own プロパティとして持つ完全な grants が
 * これまでどおりパースされ、各値が汚染値ではなく Offer が実際に告知した値であることを確認する。
 */
describe('parseGrants: 汚染下でも正当な grants をそのまま採用する', () => {
  const ALL_POLLUTED: Record<string, unknown> = {
    [PRE_AUTHORIZED_CODE_GRANT]: { 'pre-authorized_code': 'attacker-code' },
    [AUTHORIZATION_CODE_GRANT]: { issuer_state: 'attacker-state' },
    'pre-authorized_code': 'attacker-code',
    tx_code: { length: 9, input_mode: 'text' },
    length: 9,
    input_mode: 'text',
    issuer_state: 'attacker-state',
    authorization_server: 'https://attacker.example',
  };

  /** 全キーを own プロパティとして持つ正当な grants（生リテラル。`JSON.parse` を経由しない）。 */
  function honestGrants(): Record<string, unknown> {
    return {
      [PRE_AUTHORIZED_CODE_GRANT]: {
        'pre-authorized_code': 'honest-code',
        tx_code: { length: 6, input_mode: 'numeric' },
      },
      [AUTHORIZATION_CODE_GRANT]: {
        issuer_state: 'honest-state',
        authorization_server: 'https://issuer.example',
      },
    };
  }

  const FORMS: readonly (readonly [string, PollutionRunner])[] = [
    ['データ汚染', (fn) => withPollutedPrototype(ALL_POLLUTED, fn)],
    ['アクセサ汚染', (fn) => withPollutedPrototypeAccessor(toGetters(ALL_POLLUTED), fn)],
  ];

  for (const [form, run] of FORMS) {
    it(`正当な grants は Offer が告知した値どおりにパースされる（${form}）`, () => {
      const grants = expectAccepted(parseUnderPollution(run, honestGrants()));

      const preAuthorized = grants[PRE_AUTHORIZED_CODE_GRANT];
      expect(preAuthorized?.['pre-authorized_code']).toBe('honest-code');
      expect(preAuthorized?.tx_code?.length).toBe(6);
      expect(preAuthorized?.tx_code?.input_mode).toBe('numeric');

      const authorizationCode = grants[AUTHORIZATION_CODE_GRANT];
      expect(authorizationCode?.issuer_state).toBe('honest-state');
      expect(authorizationCode?.authorization_server).toBe('https://issuer.example');

      expect(Object.hasOwn(grants, PRE_AUTHORIZED_CODE_GRANT)).toBe(true);
      expect(Object.hasOwn(grants, AUTHORIZATION_CODE_GRANT)).toBe(true);
      expect(Object.hasOwn(preAuthorized as object, 'tx_code')).toBe(true);
      expect(Object.hasOwn(authorizationCode as object, 'issuer_state')).toBe(true);
      expect(Object.hasOwn(authorizationCode as object, 'authorization_server')).toBe(true);
    });
  }
});
