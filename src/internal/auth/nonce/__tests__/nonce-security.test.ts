/**
 * replay 検知のセキュリティ回帰テスト。
 *
 * いずれも修正前は「2 回目のリプレイが受理される」形で成立していた。
 *
 * 1. 期限切れ判定時にエントリを削除すると、直後の再提示が初見として通る。
 * 2. 束縛値に区切り文字 `|` を仕込むと、被害者コンテキストの容量枠に混入して
 *    消費済みエントリを LRU 退避させ、同一 nonce のリプレイが通る。
 * 3. `one-time-credential` に既定 TTL があると、VC の `exp` より前に `jti` が失効して
 *    同じ VC を別の VP に載せ替えて再利用できる。
 * 4. `get` → `set` の間に await を挟むため、直列化しないと同一 nonce の並行呼び出しが
 *    双方とも「未消費」を観測して二重消費できる（TOCTOU）。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import { contextKeyOf, entryKeyOf } from '../context-keys.js';
import { createNonceStore } from '../store.js';
import type { NonceContext } from '../types.js';

const NONCE_A = 'AQIDBAUGBwgJCgsMDQ4PEA';
const NONCE_B = 'BQIDBAUGBwgJCgsMDQ4PEA';
const VICTIM = 'https://v.example';
const CTX: NonceContext = { flow: 'oid4vp', clientId: VICTIM };

/** `VericertsError` の code を検査する（非同期版）。 */
async function expectCode(fn: () => Promise<unknown>, code: string): Promise<void> {
  try {
    await fn();
  } catch (error) {
    expect(error).toBeInstanceOf(VericertsError);
    expect((error as VericertsError).code).toBe(code as never);
    return;
  }
  throw new Error('例外が送出されなかった');
}

describe('回帰: 期限切れ判定でエントリを削除しない', () => {
  it('期限切れ nonce を再提示しても毎回 4011 で、初見として受理されない', async () => {
    let currentMs = 1_700_000_000_000;
    const store = createNonceStore({ backend: 'memory', now: () => currentMs });
    await store.put(NONCE_A, CTX, 1000);
    currentMs += 5000;

    // 修正前は 1 回目で削除され、2 回目が「初見」として成功していた。
    await expectCode(() => store.checkAndUse(NONCE_A, CTX), ErrorCodes.NONCE_EXPIRED);
    await expectCode(() => store.checkAndUse(NONCE_A, CTX), ErrorCodes.NONCE_EXPIRED);
    await expectCode(() => store.checkAndUse(NONCE_A, CTX), ErrorCodes.NONCE_EXPIRED);
  });

  it('消費済み nonce が期限切れになっても初見として受理されない', async () => {
    let currentMs = 1_700_000_000_000;
    const store = createNonceStore({ backend: 'memory', now: () => currentMs });
    await store.checkAndUse(NONCE_A, CTX, { ttlMs: 1000 });
    currentMs += 5000;
    await expectCode(() => store.checkAndUse(NONCE_A, CTX), ErrorCodes.NONCE_EXPIRED);
  });
});

describe('回帰: 束縛値の区切り文字インジェクション', () => {
  it('clientId に | を含むコンテキストは別のキー空間になる', () => {
    const victim: NonceContext = { flow: 'oid4vp', clientId: VICTIM };
    const attacker: NonceContext = { flow: 'oid4vp', clientId: `${VICTIM}|atkN` };

    // 攻撃者のエントリキーが被害者のプレフィックスで前方一致してはならない。
    expect(entryKeyOf(NONCE_A, attacker).startsWith(`${contextKeyOf(victim)}|`)).toBe(false);
    expect(contextKeyOf(attacker)).not.toBe(contextKeyOf(victim));
  });

  it('攻撃者が容量枠を埋めても被害者の消費済み nonce は退避されずリプレイが通らない', async () => {
    const store = createNonceStore({ backend: 'memory', maxEntries: 2 });
    const attacker: NonceContext = { flow: 'oid4vp', clientId: `${VICTIM}|atkN` };

    await store.checkAndUse(NONCE_A, CTX, { ttlMs: 600_000 });
    expect(await store.has(NONCE_A, CTX)).toBe(true);

    // 攻撃者コンテキストで上限を超える件数を投入する（発行記録の `put` は無認証で呼ばせられる）。
    // エスケープが無いと、これらのキーが被害者のプレフィックスで前方一致し、被害者の容量枠を圧迫する。
    for (const c of ['C', 'D', 'E', 'F']) {
      await store.put(`${c}QIDBAUGBwgJCgsMDQ4PEA`, attacker, 600_000);
    }

    // 被害者自身の次の挿入で LRU 退避が走る。ここで NONCE_A が退避されるとリプレイが通る。
    await store.checkAndUse(NONCE_B, CTX, { ttlMs: 600_000 });

    // 被害者の消費済みエントリは生存し、同一 nonce のリプレイは拒否される。
    expect(await store.has(NONCE_A, CTX)).toBe(true);
    await expectCode(() => store.checkAndUse(NONCE_A, CTX), ErrorCodes.REPLAY_DETECTED);
  });

  it('コロンを含む束縛値でも flow 境界を越えない', () => {
    const a: NonceContext = { flow: 'oid4vp', clientId: 'x' };
    const b: NonceContext = { flow: 'oid4vci', issuer: 'x' };
    expect(contextKeyOf(a)).not.toBe(contextKeyOf(b));
    expect(entryKeyOf(NONCE_B, a)).not.toBe(entryKeyOf(NONCE_B, b));
  });
});

describe('回帰: one-time-credential は TTL 明示が必須', () => {
  it('ttlMs 未指定の checkAndUse は RangeError（既定 TTL で早期失効させない）', async () => {
    const store = createNonceStore({ backend: 'memory' });
    const ctx: NonceContext = { flow: 'one-time-credential', issuer: 'did:example:issuer' };
    await expect(
      store.checkAndUse('f81d4fae-7dec-41d0-a765-00a0c91e6bf6', ctx),
    ).rejects.toBeInstanceOf(RangeError);
  });

  it('oid4vp は TTL を省略して nonce を消費できる', async () => {
    const store = createNonceStore({ backend: 'memory' });
    await expect(store.checkAndUse(NONCE_A, CTX)).resolves.toBeUndefined();
  });
});

describe('回帰: 同一 nonce の並行消費（TOCTOU 二重消費）', () => {
  it('並行 checkAndUse は 1 回だけ成功し、残りは 4010 になる', async () => {
    const store = createNonceStore({ backend: 'memory' });
    const results = await Promise.allSettled([
      store.checkAndUse(NONCE_A, CTX),
      store.checkAndUse(NONCE_A, CTX),
      store.checkAndUse(NONCE_A, CTX),
    ]);

    // 修正前は 3 件すべてが成功していた（リプレイ検知の完全な回避）。
    expect(results.filter((r) => r.status === 'fulfilled')).toHaveLength(1);
    for (const rejected of results.filter((r) => r.status === 'rejected')) {
      const reason = (rejected as PromiseRejectedResult).reason as VericertsError;
      expect(reason).toBeInstanceOf(VericertsError);
      expect(reason.code).toBe(ErrorCodes.REPLAY_DETECTED as never);
    }
  });

  it('発行済み nonce への並行 checkAndUse も 1 回だけ成功する', async () => {
    const store = createNonceStore({ backend: 'memory' });
    await store.put(NONCE_B, CTX, 600_000);
    const results = await Promise.allSettled([
      store.checkAndUse(NONCE_B, CTX),
      store.checkAndUse(NONCE_B, CTX),
    ]);
    expect(results.filter((r) => r.status === 'fulfilled')).toHaveLength(1);
  });

  it('異なる nonce の並行消費は互いにブロックしない', async () => {
    const store = createNonceStore({ backend: 'memory' });
    const results = await Promise.all([
      store.checkAndUse(NONCE_A, CTX),
      store.checkAndUse(NONCE_B, CTX),
    ]);
    expect(results).toHaveLength(2);
  });
});
