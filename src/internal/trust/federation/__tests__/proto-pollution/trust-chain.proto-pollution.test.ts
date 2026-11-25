/**
 * Federation Trust Chain の依存注入の `Object.prototype` 汚染耐性テスト
 *
 * `deps.now` をプロトタイプ鎖で読むと、`now` を**省略した**正当なチェーン構築でも汚染値が
 * 基準時刻として使われる。Entity Statement の有効期間（`iat` / `exp`）と鍵無効化
 * （`revoked_at`）の突合は検証時刻基準なので、攻撃者が時刻を選べると**期限切れの Statement で
 * 組んだチェーンが成立する**。
 *
 * `deps.fetchFn` の継承値は Statement の取得先そのものを攻撃者の関数へ委譲する。
 *
 * `fetchFn` 側の検証は「汚染値ではなくフォールバック先のグローバル `fetch` が使われた」ことを
 * スパイで直接観測する。実 fetch の失敗を当てにすると所要時間が DNS / ネットワーク依存になり
 * フレークするため。
 */

import { describe, expect, it } from 'bun:test';
import { withPollutedPrototypeAsync } from '../../../../__tests__/prototype-pollution.fixtures.js';
import { VericertsError } from '../../../../errors.js';
import type { TrustChain } from '../../federation-types.js';
import { buildTrustChain } from '../../trust-chain.js';
import { buildValidTopology, makeFetchMock, nowFn } from '../federation-fixtures.js';

/** `fetch` の第 1 引数から要求 URL を取り出す（スパイの記録用）。 */
function requestUrl(input: string | URL | Request): string {
  if (typeof input === 'string') {
    return input;
  }
  return input instanceof URL ? input.toString() : input.url;
}

describe('buildTrustChain の依存注入 汚染耐性', () => {
  it('継承した now は検証時刻として採用しない', async () => {
    const topo = buildValidTopology();
    // フィクスチャの Statement は `nowFn`（固定時刻）基準でのみ有効。`now` を渡さない呼び出しで
    // 汚染値を拾えばチェーンが成立してしまう。own 限定で読めば実時刻で評価され、
    // 有効期間外として TRUST_CHAIN_INVALID になる。
    let caught: unknown;
    try {
      await withPollutedPrototypeAsync({ now: nowFn }, () =>
        buildTrustChain(topo.leafId, topo.anchorId, {
          fetchFn: makeFetchMock(topo.responses),
        }),
      );
    } catch (error) {
      caught = error;
    }
    expect(caught).toBeInstanceOf(VericertsError);
  });

  it('継承した fetchFn は Statement の取得先として採用しない', async () => {
    const topo = buildValidTopology();
    let attackerFetchCalls = 0;
    const attackerFetch = makeFetchMock(topo.responses);
    // `fetchFn` 未指定時のフォールバック先（グローバル `fetch`）を、同じトポロジ応答を返す
    // スパイへ差し替える。汚染値が採用されれば `attackerFetchCalls` が増えてこのスパイは
    // 呼ばれず、`Object.prototype` 由来を採用しなければその逆になるので、どちらが取得先に
    // 使われたかを直接観測できる（`fetchFn` の読み取りは own 限定ではなく
    // `nonObjectPrototypeProperty`。関数値の DI を own 限定で読むと、注入した証明書ピンニング
    // 付き fetch が無言でグローバル fetch へ差し替わる fail-open になるため。実ネットワークへは
    // 出ないので DNS / 接続の遅延にも依存しない）。
    const topologyFetch = makeFetchMock(topo.responses);
    const globalFetchUrls: string[] = [];
    const originalFetch = globalThis.fetch;
    globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
      globalFetchUrls.push(requestUrl(input));
      return topologyFetch(input, init);
    }) as unknown as typeof fetch;
    let chain: TrustChain;
    try {
      chain = await withPollutedPrototypeAsync(
        {
          fetchFn: (...args: Parameters<typeof fetch>): ReturnType<typeof fetch> => {
            attackerFetchCalls += 1;
            return attackerFetch(...args);
          },
        },
        () => buildTrustChain(topo.leafId, topo.anchorId, { now: nowFn }),
      );
    } finally {
      globalThis.fetch = originalFetch;
    }
    // 汚染 fetch は一度も呼ばれず、フォールバック先のグローバル fetch が取得先として使われる。
    expect(attackerFetchCalls).toBe(0);
    expect(globalFetchUrls).toContain(`${topo.leafId}/.well-known/openid-federation`);
    expect(chain.valid).toBe(true);
  });

  it('明示的に渡した now / fetchFn は従来どおり効く（正常系）', async () => {
    const topo = buildValidTopology();
    const chain = await buildTrustChain(topo.leafId, topo.anchorId, {
      fetchFn: makeFetchMock(topo.responses),
      now: nowFn,
    });
    expect(chain.valid).toBe(true);
    expect(chain.leaf).toBe(topo.leafId);
  });
});
