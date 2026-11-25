/**
 * `resolveCachedStatement` の deps（statementCache / onCacheEvent / maxTtlSeconds）は鎖を辿らない。
 *
 * `request.deps.statementCache` が鎖読みだと、キャッシュ未注入（= 毎回取得して検証）の呼び出しが
 * `Object.prototype.statementCache` の汚染オブジェクトを共有キャッシュとして使い、そこに入れた JWT
 * を返す（検証は通すが、取得を迂回できる）。観測フックも同様に汚染関数へ差し替わる。
 */

import { describe, expect, it } from 'bun:test';
import { withPollutedPrototypeAsync } from '../../../../__tests__/prototype-pollution.fixtures.js';
import { resolveCachedStatement } from '../../cache/statement-cache.js';
import { NOW_SECONDS } from '../federation-fixtures.js';

const KEY = 'https://leaf.example.eu/.well-known/openid-federation';
const PERIOD = { iat: NOW_SECONDS - 3600, exp: NOW_SECONDS + 3600 };

function request(fetched: string[], verified: string[]) {
  return {
    key: KEY,
    kind: 'entity-configuration' as const,
    deps: {},
    nowSeconds: NOW_SECONDS,
    fetchJwt: async () => {
      fetched.push('fetch');
      return 'fetched.jwt';
    },
    verify: (jwt: string) => {
      verified.push(jwt);
      return { value: jwt, statement: PERIOD };
    },
  };
}

describe('resolveCachedStatement: deps の継承値', () => {
  it('汚染された statementCache（攻撃者の JWT を返すキャッシュ）は使われず、毎回取得して検証する', async () => {
    const stored: string[] = [];
    const attackerCache = {
      get: () => 'attacker.jwt',
      set: (_key: string, value: string) => {
        stored.push(value);
      },
    };
    const fetched: string[] = [];
    const verified: string[] = [];
    const result = await withPollutedPrototypeAsync({ statementCache: attackerCache }, () =>
      resolveCachedStatement(request(fetched, verified)),
    );
    expect(result).toBe('fetched.jwt');
    expect(fetched).toEqual(['fetch']);
    expect(verified).toEqual(['fetched.jwt']);
    expect(stored).toEqual([]);
  });

  it('汚染された onCacheEvent は呼ばれない', async () => {
    const events: unknown[] = [];
    await withPollutedPrototypeAsync({ onCacheEvent: (event: unknown) => events.push(event) }, () =>
      resolveCachedStatement(request([], [])),
    );
    expect(events).toEqual([]);
  });
});
