/**
 * `rebuildDpop`（DPoP nonce 再送の proof 再生成関数。RFC 9449 §8 / §9）の `Object.prototype`
 * 汚染耐性（実装は `dpop-nonce/index.ts` の `readDpopRebuilder`）。
 *
 * `rebuildDpop` を鎖読みすると、指定していない正当な呼び出しが `use_dpop_nonce` を受けた再送時に
 * `Object.prototype.rebuildDpop` の汚染関数を呼び、攻撃者の proof を `DPoP` ヘッダへ載せうる。
 * `dpop` は own 限定で読むのに `rebuildDpop` だけ鎖読みへ戻っても、既存の `dpop` 向け汚染テストは
 * 赤くならないため、Token（pre-authorized / authorization_code）・Credential・PAR の全要求経路で
 * 「汚染関数が呼ばれず、再送もされない（fetch は 1 回）」ことと、正当に own 指定した
 * `rebuildDpop` は従来どおり 1 回だけ再送されること（ポジティブコントロール）を固定する。
 */

import { describe, expect, it } from 'bun:test';
import { withPollutedPrototypeAsync } from '../../../../__tests__/prototype-pollution.fixtures.js';
import type { FetchLike } from '../../oid4vci.js';
import { requestCredential } from '../../oid4vci.js';
import { pushAuthorizationRequest } from '../../par/index.js';
import {
  requestTokenAuthorizationCode,
  requestTokenPreAuthorized,
} from '../../token/oid4vci-token.js';
import { baseRequest } from '../par/par-fixtures.js';

const NONCE = 'server-nonce';
const OWN_DPOP = 'own-proof';
const ATTACKER_PROOF = 'attacker-proof';

/** AS（Token / PAR）の `400 use_dpop_nonce`（RFC 9449 §8）。 */
const asChallenge = (): Response =>
  new Response(JSON.stringify({ error: 'use_dpop_nonce' }), {
    status: 400,
    headers: { 'Content-Type': 'application/json', 'DPoP-Nonce': NONCE },
  });

/** RS（Credential）の `401 WWW-Authenticate: DPoP error="use_dpop_nonce"`（§9）。 */
const rsChallenge = (): Response =>
  new Response('', {
    status: 401,
    headers: { 'WWW-Authenticate': 'DPoP error="use_dpop_nonce"', 'DPoP-Nonce': NONCE },
  });

/** 常にチャレンジを返し、`DPoP` ヘッダを記録する fetch スタブ。 */
function challengingFetch(challenge: () => Response): { fetchImpl: FetchLike; dpops: unknown[] } {
  const dpops: unknown[] = [];
  return {
    dpops,
    fetchImpl: async (_url, init) => {
      dpops.push(init.headers.DPoP);
      return challenge();
    },
  };
}

interface Route {
  readonly name: string;
  readonly challenge: () => Response;
  /** `rebuildDpop`（own 指定時のみ）と `dpop` を載せて要求を 1 回呼ぶ。 */
  readonly run: (
    fetchImpl: FetchLike,
    rebuildDpop: ((nonce: string) => string) | undefined,
  ) => Promise<unknown>;
}

/** 指定時だけ own プロパティとして `rebuildDpop` を足す（`undefined` を own に置かない）。 */
function withRebuild<T extends object>(
  base: T,
  rebuildDpop: ((nonce: string) => string) | undefined,
): T {
  return rebuildDpop === undefined ? base : { ...base, rebuildDpop };
}

const ROUTES: Route[] = [
  {
    name: 'requestTokenPreAuthorized',
    challenge: asChallenge,
    run: (fetchImpl, rebuildDpop) =>
      requestTokenPreAuthorized(
        'https://issuer.example.com/token',
        withRebuild({ preAuthorizedCode: 'code', dpop: OWN_DPOP, fetchImpl }, rebuildDpop),
      ),
  },
  {
    name: 'requestTokenAuthorizationCode',
    challenge: asChallenge,
    run: (fetchImpl, rebuildDpop) =>
      requestTokenAuthorizationCode(
        'https://issuer.example.com/token',
        withRebuild(
          { code: 'code', codeVerifier: 'verifier', dpop: OWN_DPOP, fetchImpl },
          rebuildDpop,
        ),
      ),
  },
  {
    name: 'requestCredential',
    challenge: rsChallenge,
    run: (fetchImpl, rebuildDpop) =>
      requestCredential(
        withRebuild(
          {
            credentialEndpoint: 'https://issuer.example.com/credential',
            accessToken: 'access-token',
            format: 'jwt_vc_json',
            credentialDefinition: { type: ['VerifiableCredential'] },
            proofJwt: 'eyJ.proof.jwt',
            dpop: OWN_DPOP,
            fetchImpl,
          },
          rebuildDpop,
        ),
      ),
  },
  {
    name: 'pushAuthorizationRequest',
    challenge: asChallenge,
    run: (fetchImpl, rebuildDpop) =>
      pushAuthorizationRequest(
        withRebuild({ ...baseRequest(fetchImpl), dpop: OWN_DPOP }, rebuildDpop),
      ),
  },
];

describe('rebuildDpop の Object.prototype 汚染耐性', () => {
  it.each(ROUTES)('$name: 継承した rebuildDpop は呼ばず、nonce 再送もしない', async (route) => {
    const stub = challengingFetch(route.challenge);
    let polluted = 0;
    await withPollutedPrototypeAsync(
      {
        rebuildDpop: () => {
          polluted += 1;
          return ATTACKER_PROOF;
        },
      },
      () => route.run(stub.fetchImpl, undefined).catch(() => undefined),
    );
    expect(polluted).toBe(0);
    // 再送されないので fetch は初回の 1 回だけ。攻撃者の proof は `DPoP` ヘッダに載らない。
    expect(stub.dpops).toEqual([OWN_DPOP]);
  });

  // ポジティブコントロール。「常に再送しない」実装へ退行しても上の検査は通ってしまうため、
  // 同じ汚染下で own 指定の rebuildDpop が（汚染関数ではなく）使われることも示す。
  it.each(
    ROUTES,
  )('$name: 汚染下でも own 指定の rebuildDpop は 1 回だけ再送に使われる', async (route) => {
    const stub = challengingFetch(route.challenge);
    let polluted = 0;
    const nonces: string[] = [];
    await withPollutedPrototypeAsync(
      {
        rebuildDpop: () => {
          polluted += 1;
          return ATTACKER_PROOF;
        },
      },
      () =>
        route
          .run(stub.fetchImpl, (nonce) => {
            nonces.push(nonce);
            return `rebuilt(${nonce})`;
          })
          .catch(() => undefined),
    );
    expect(polluted).toBe(0);
    expect(nonces).toEqual([NONCE]);
    expect(stub.dpops).toEqual([OWN_DPOP, `rebuilt(${NONCE})`]);
  });
});
