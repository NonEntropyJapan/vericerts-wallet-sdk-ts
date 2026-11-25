/**
 * Federation Entity Statement キャッシュ層テストの共有ヘルパ。
 *
 * 可変時計・呼び出し回数を数える fetch モック・キャッシュ・観測イベント収集を 1 つにまとめる。
 * 同ディレクトリのテストは「何回ネットワークに出たか」と「cold / warm / hot の遷移」で
 * キャッシュ挙動を判定するため、この 2 つを同じ harness から取れるようにしてある。
 *
 * テスト本体は Linterly の 1 ファイル 300 行上限に収めるため観点ごとに分割してあり、
 * 本ファイルはそのいずれからも import される（テストケースは含まない）。
 */

import { expect } from 'bun:test';
import { type ErrorCode, VericertsError } from '../../../../errors.js';
import {
  createFederationStatementCache,
  type FederationCacheEvent,
} from '../../cache/statement-cache.js';
import { LEAF_KEY, NOW_SECONDS, signStatement, toJwk } from '../federation-fixtures.js';

/** テスト対象の Entity Identifier。 */
export const ENTITY_ID = 'https://leaf.example.eu';
/** `ENTITY_ID` の Entity Configuration well-known URL（＝キャッシュキー）。 */
export const WELL_KNOWN = `${ENTITY_ID}/.well-known/openid-federation`;
/** 1 年（秒）。TTL 上限 600 秒が `exp` より先に効くことを示すために使う。 */
export const YEAR_SECONDS = 365 * 24 * 3600;

/**
 * reject が指定コードの VericertsError であることを検証し、その例外を返す。
 *
 * @param promise 失敗が期待される Promise。
 * @param code 期待するエラーコード。
 * @returns 捕捉した VericertsError（メッセージ・context の追加検証用）。
 */
export async function expectRejectCode(
  promise: Promise<unknown>,
  code: ErrorCode,
): Promise<VericertsError> {
  let caught: unknown;
  try {
    await promise;
  } catch (error) {
    caught = error;
  }
  expect(caught).toBeInstanceOf(VericertsError);
  const failure = caught as VericertsError;
  expect(failure.code).toBe(code);
  return failure;
}

/**
 * URL → 本文（JWT）を返す fetch モック。呼び出し回数を数える。未登録 URL は 404。
 *
 * @param bodyFor URL に対する応答本文を返す関数（undefined なら 404）。
 * @returns fetch 関数と呼び出し回数の取得関数。
 */
export function countingFetch(bodyFor: (url: string) => string | undefined): {
  fetchFn: typeof fetch;
  count: () => number;
} {
  let calls = 0;
  const fetchFn = (async (input: string | URL): Promise<Response> => {
    calls += 1;
    const body = bodyFor(typeof input === 'string' ? input : input.toString());
    if (body === undefined) {
      return new Response('nf', { status: 404 });
    }
    return new Response(body, {
      status: 200,
      headers: { 'content-type': 'application/entity-statement+jwt' },
    });
  }) as typeof fetch;
  return { fetchFn, count: () => calls };
}

/**
 * `ENTITY_ID` の自己署名 Entity Configuration を組み立てる。
 *
 * @param iat 発行時刻（エポック秒）。
 * @param exp 失効時刻（エポック秒）。TTL の上界を決める。
 * @returns compact JWS 文字列。
 */
export function selfSigned(iat: number, exp: number): string {
  return signStatement(
    LEAF_KEY,
    { iss: ENTITY_ID, sub: ENTITY_ID, iat, exp, jwks: { keys: [toJwk(LEAF_KEY, 'leaf-1')] } },
    { kid: 'leaf-1' },
  );
}

/**
 * 可変時計・カウント付き fetch・キャッシュ・観測イベント一式を用意する。
 *
 * @param bodyFor URL に対する応答本文を返す関数。
 * @returns 観測イベント配列・取得回数・キャッシュ本体・時計の前進関数・注入用 deps。
 */
export function harness(bodyFor: (url: string) => string | undefined) {
  let now = NOW_SECONDS;
  const events: FederationCacheEvent[] = [];
  const { fetchFn, count } = countingFetch(bodyFor);
  const statementCache = createFederationStatementCache(() => now);
  return {
    events,
    count,
    statementCache,
    advance: (seconds: number): void => {
      now += seconds;
    },
    deps: {
      fetchFn,
      now: (): number => now * 1000,
      statementCache,
      onCacheEvent: (event: FederationCacheEvent): void => {
        events.push(event);
      },
    },
  };
}
