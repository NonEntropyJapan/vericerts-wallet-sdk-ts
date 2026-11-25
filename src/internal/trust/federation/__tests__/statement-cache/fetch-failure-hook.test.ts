/**
 * `resolveCachedStatement` の取得失敗フック（`onFetchFailure`、FO-6 の受け口）の回帰テスト。
 *
 * 検証内容:
 * - フック未設定なら従来どおり取得失敗をそのまま送出する（既定は fail-closed のまま）。
 * - TTL 切れのエントリがあれば stale な JWT をフックへ渡し、返ってきた JWT は**必ず再検証**される。
 * - エントリが無ければ `staleJwt: undefined` を渡す（呼び出し側が fail-closed を選べるようにする）。
 * - **negative cache 命中時もフックを呼ぶ**。ここを漏らすと取得失敗の記憶が生きている 30 秒だけ
 *   FO-6 が発動せず、継続的な障害中に通過と拒否が周期的に入れ替わる。
 * - `Object.prototype` 汚染でフックを生やしても発動しない（フック未設定の経路を守る）。
 */

import { describe, expect, it } from 'bun:test';
import { withPollutedPrototypeAsync } from '../../../../__tests__/prototype-pollution.fixtures.js';
import {
  type CachedStatementRequest,
  createFederationStatementCache,
  resolveCachedStatement,
} from '../../cache/statement-cache.js';
import type { StatementFetchFailure } from '../../fail-open/fetch-failure.js';
import { NOW_SECONDS } from '../federation-fixtures.js';

const KEY = 'https://leaf.example.eu/.well-known/openid-federation';
const STALE_JWT = 'stale.jwt.token';
const PERIOD = { iat: NOW_SECONDS - 3600, exp: NOW_SECONDS + 3600 };

/** 取得は常に失敗する（FO-6 の入口となる唯一の条件）。 */
const FETCH_ERROR = new Error('network down');

/** フックの観測結果と、リクエストを組み立てる関数一式。 */
function harness(options: { readonly substitute?: string; readonly withHook: boolean }) {
  let now = NOW_SECONDS;
  const statementCache = createFederationStatementCache(() => now);
  const seen: StatementFetchFailure[] = [];
  const verified: string[] = [];
  const hook = async (failure: StatementFetchFailure): Promise<string | undefined> => {
    seen.push(failure);
    return options.substitute;
  };
  const request = (): CachedStatementRequest<string> => ({
    key: KEY,
    kind: 'entity-configuration',
    deps: { statementCache },
    nowSeconds: now,
    fetchJwt: () => Promise.reject(FETCH_ERROR),
    verify: (jwt: string) => {
      verified.push(jwt);
      return { value: `verified:${jwt}`, statement: PERIOD };
    },
    ...(options.withHook ? { onFetchFailure: hook } : {}),
  });
  return {
    seen,
    verified,
    statementCache,
    request,
    advance: (seconds: number): void => {
      now += seconds;
    },
    /** TTL 切れのエントリを 1 件作る（TTL 60 秒で格納し、その先まで時計を進める）。 */
    primeStale: (): void => {
      statementCache.set(KEY, STALE_JWT, 60, now);
      now += 120;
    },
  };
}

describe('onFetchFailure 未設定（従来動作）', () => {
  it('TTL 切れのエントリがあっても取得失敗をそのまま送出する', async () => {
    const h = harness({ withHook: false });
    h.primeStale();
    await expect(resolveCachedStatement(h.request())).rejects.toThrow(FETCH_ERROR);
    expect(h.verified).toEqual([]);
  });

  it('Object.prototype 汚染でフックを生やしても救済されない', async () => {
    const h = harness({ withHook: false });
    h.primeStale();
    await withPollutedPrototypeAsync(
      { onFetchFailure: async (): Promise<string> => STALE_JWT },
      async () => {
        await expect(resolveCachedStatement(h.request())).rejects.toThrow(FETCH_ERROR);
      },
    );
    expect(h.verified).toEqual([]);
  });
});

describe('onFetchFailure 設定時', () => {
  it('TTL 切れのエントリ（warm）では stale な JWT を渡し、返した JWT を再検証して返す', async () => {
    const h = harness({ withHook: true, substitute: STALE_JWT });
    h.primeStale();
    expect(await resolveCachedStatement(h.request())).toBe(`verified:${STALE_JWT}`);
    expect(h.seen).toHaveLength(1);
    expect(h.seen[0]?.staleJwt).toBe(STALE_JWT);
    expect(h.seen[0]?.error).toBe(FETCH_ERROR);
    // 代替 JWT も必ず `verify` を通る（キャッシュ層の再検証の不変条件）。
    expect(h.verified).toEqual([STALE_JWT]);
  });

  it('エントリが無い（cold）場合は staleJwt が undefined になる', async () => {
    const h = harness({ withHook: true });
    await expect(resolveCachedStatement(h.request())).rejects.toThrow(FETCH_ERROR);
    expect(h.seen).toHaveLength(1);
    expect(h.seen[0]?.staleJwt).toBeUndefined();
  });

  it('代替 JWT の検証が失敗すればその例外が伝播する（再検証を飛ばさない）', async () => {
    const h = harness({ withHook: true, substitute: STALE_JWT });
    h.primeStale();
    const request: CachedStatementRequest<string> = {
      ...h.request(),
      verify: () => {
        throw new Error('invalid statement');
      },
    };
    await expect(resolveCachedStatement(request)).rejects.toThrow('invalid statement');
  });

  it('フックが undefined を返せば元の失敗をそのまま送出する', async () => {
    const h = harness({ withHook: true });
    h.primeStale();
    await expect(resolveCachedStatement(h.request())).rejects.toThrow(FETCH_ERROR);
    expect(h.seen[0]?.staleJwt).toBe(STALE_JWT);
  });

  // 回帰の中心: negative cache（30 秒）命中の経路でフックを呼ばないと、障害継続中に
  // 1 回目だけ通過し以降 30 秒は拒否、という周期的な挙動になる。
  it('negative cache 命中時もフックを呼ぶ（30 秒の谷間で FO-6 が消えない）', async () => {
    const h = harness({ withHook: true, substitute: STALE_JWT });
    h.primeStale();
    expect(await resolveCachedStatement(h.request())).toBe(`verified:${STALE_JWT}`);
    // 1 回目の失敗が negative cache に記憶されている間（30 秒未満）に再実行する。
    h.advance(10);
    expect(await resolveCachedStatement(h.request())).toBe(`verified:${STALE_JWT}`);
    expect(h.seen).toHaveLength(2);
    expect(h.seen[1]?.staleJwt).toBe(STALE_JWT);
    expect(h.verified).toEqual([STALE_JWT, STALE_JWT]);
  });
});
