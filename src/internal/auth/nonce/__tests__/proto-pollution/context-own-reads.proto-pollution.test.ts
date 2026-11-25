/**
 * `bindingValueOf` / `contextKeyOf` / `entryKeyOf` の `NonceContext` 鎖読みの回帰テスト。
 *
 * 以前は `verifySdJwtWithReplayGuard` / `verifyPresentationWithReplayGuard` の 2 ラッパ経由では
 * `nonceContext` / `nonceContext.flow` を own 検証して塞いだが、束縛値そのものを取り出す
 * `bindingValueOf` には鎖読みが残っており、**`NonceStore#checkAndUse` を直接呼ぶ経路**に穴がある。
 *
 * `ctx.flow` / `ctx.clientId` / `ctx.issuer` / `ctx.audience` / `ctx.jkt` を鎖読みすると、
 * 当該メンバを own に持たない `nonceContext` ＋ `Object.prototype` 汚染下で
 * **`aud` 照合の対象も拒否リストのキー空間も攻撃者が選んだ値になる**。`flow` の鎖読みは
 * さらに強く、**どのメンバを束縛値として読むかの選択自体**を攻撃者に握らせる。
 *
 * `checkAndUse` の `opts` 側（`binding` / `ttlMs`）も同じ規律で own 限定に揃える。`ttlMs` の
 * 鎖読みは初見 nonce を即時失効させ、prune 後の再消費を「初見」として受理させる。
 *
 * 期待値は「当該メンバを own に持たない context は `NONCE_BINDING_MISMATCH`(4012) で fail-closed に
 * 拒否される（汚染値を束縛対象・キー空間に採用しない）」。`guard.ts` / `vp-guard.ts` が同一条件を
 * 4012 で扱うのと揃える（4013 は nonce **値**の形式不正）。
 * 修正を鎖読みへ戻すと本ファイルの各テストは失敗する。
 */

import { describe, expect, it } from 'bun:test';
import {
  withPollutedPrototype,
  withPollutedPrototypeAsync,
} from '../../../../__tests__/prototype-pollution.fixtures.js';
import { ErrorCodes, VericertsError } from '../../../../errors.js';
import { assertBinding, bindingValueOf } from '../../context.js';
import { contextKeyOf, entryKeyOf } from '../../context-keys.js';
import { createNonceStore } from '../../store.js';
import type { NonceContext, NonceStore } from '../../types.js';

const NONCE = 'AQIDBAUGBwgJCgsMDQ4PEA';
const VICTIM_CLIENT = 'https://verifier.example/client';
const ATTACKER_CLIENT = 'https://evil.example/client';
const ATTACKER_ISSUER = 'https://evil.example/issuer';
const NOW_MS = 1_700_000_000_000;

/** 固定時刻の `NonceStore` を作る。 */
function makeStore(): NonceStore {
  return createNonceStore({ backend: 'memory', now: () => NOW_MS });
}

/** 進められる時計を持つ `NonceStore` を作る。 */
function makeAdvancingStore(): { store: NonceStore; advance: (ms: number) => void } {
  let now = NOW_MS;
  const store = createNonceStore({ backend: 'memory', now: () => now });
  return {
    store,
    advance: (ms: number) => {
      now += ms;
    },
  };
}

/** `flow` だけを持ち束縛値メンバを own に持たない context。 */
function ctxWithoutBinding(flow: string): NonceContext {
  return { flow } as unknown as NonceContext;
}

/** 4012 で拒否されることを表明する。 */
function expectBindingMismatch(fn: () => unknown): void {
  try {
    fn();
  } catch (e) {
    expect(e).toBeInstanceOf(VericertsError);
    expect((e as VericertsError).code).toBe(ErrorCodes.NONCE_BINDING_MISMATCH);
    return;
  }
  throw new Error('汚染下で素通りした（fail-open）');
}

describe('bindingValueOf / prototype pollution', () => {
  it('正常系: own の束縛値は従来どおり取り出される', () => {
    expect(bindingValueOf({ flow: 'oid4vp', clientId: VICTIM_CLIENT })).toBe(VICTIM_CLIENT);
    expect(bindingValueOf({ flow: 'oid4vci', issuer: 'https://issuer.example' })).toBe(
      'https://issuer.example',
    );
    expect(bindingValueOf({ flow: 'wua-pop', audience: 'https://as.example' })).toBe(
      'https://as.example',
    );
    expect(bindingValueOf({ flow: 'dpop', jkt: 'thumbprint' })).toBe('thumbprint');
  });

  it('`clientId` を own に持たない context は汚染下でも束縛値を採用しない', () => {
    const ctx = ctxWithoutBinding('oid4vp');
    withPollutedPrototype({ clientId: ATTACKER_CLIENT }, () => {
      expectBindingMismatch(() => bindingValueOf(ctx));
    });
  });

  it('`issuer` を own に持たない context は汚染下でも束縛値を採用しない', () => {
    const ctx = ctxWithoutBinding('oid4vci');
    withPollutedPrototype({ issuer: ATTACKER_ISSUER }, () => {
      expectBindingMismatch(() => bindingValueOf(ctx));
    });
  });

  it('`audience` を own に持たない context は汚染下でも束縛値を採用しない', () => {
    const ctx = ctxWithoutBinding('wua-pop');
    withPollutedPrototype({ audience: 'https://evil.example' }, () => {
      expectBindingMismatch(() => bindingValueOf(ctx));
    });
  });

  it('`jkt` を own に持たない context は汚染下でも束縛値を採用しない', () => {
    const ctx = ctxWithoutBinding('dpop');
    withPollutedPrototype({ jkt: 'attacker-thumbprint' }, () => {
      expectBindingMismatch(() => bindingValueOf(ctx));
    });
  });

  it('`flow` を own に持たない context は汚染下でもキー空間を採用しない', () => {
    const ctx = {} as unknown as NonceContext;
    withPollutedPrototype({ flow: 'oid4vp', clientId: ATTACKER_CLIENT }, () => {
      expectBindingMismatch(() => bindingValueOf(ctx));
      expectBindingMismatch(() => contextKeyOf(ctx));
      expectBindingMismatch(() => entryKeyOf(NONCE, ctx));
    });
  });

  it('束縛値を own に持つが `flow` を own に持たない context も汚染下で拒否される', () => {
    // 束縛値は own にあるため、`flow` の own 読みだけが唯一の防御線になる（束縛値側の
    // own 読みで先に落ちるケースでは `flow` の鎖読みが pin されない）。
    const ctx = { clientId: VICTIM_CLIENT } as unknown as NonceContext;
    withPollutedPrototype({ flow: 'oid4vp' }, () => {
      // 鎖読みだと flow='oid4vp' が採用され、own の `clientId` がそのまま束縛値になる。
      expectBindingMismatch(() => bindingValueOf(ctx));
      expectBindingMismatch(() => contextKeyOf(ctx));
      expectBindingMismatch(() => entryKeyOf(NONCE, ctx));
      expectBindingMismatch(() => assertBinding(ctx, VICTIM_CLIENT));
    });
  });

  it('`flow` の汚染で束縛メンバの選択自体を差し替えられない', () => {
    // `clientId` / `issuer` を両方 own に持つ context で `flow` だけを汚染すると、
    // 鎖読みでは flow='oid4vci' が採用されて**束縛値が `issuer`（攻撃者の値）に切り替わる**。
    const ctx = {
      clientId: VICTIM_CLIENT,
      issuer: ATTACKER_ISSUER,
    } as unknown as NonceContext;
    withPollutedPrototype({ flow: 'oid4vci' }, () => {
      expectBindingMismatch(() => bindingValueOf(ctx));
      // 攻撃者の `issuer` が束縛対象として採用されていれば一致して素通りする。
      expectBindingMismatch(() => assertBinding(ctx, ATTACKER_ISSUER));
    });
  });

  it('既知 flow の判定表は汚染で拡張されない（未知 flow は 4012）', () => {
    // 対応表 `BINDING_MEMBER_BY_FLOW` 自身を鎖読みすると、汚染で**未知の flow が既知に化け**、
    // ホワイトリスト検証を素通りして攻撃者の選んだキー空間（`evil-flow:<値>`）が成立する。
    const ctx = { flow: 'evil-flow', clientId: VICTIM_CLIENT } as unknown as NonceContext;
    withPollutedPrototype({ 'evil-flow': 'clientId' }, () => {
      expectBindingMismatch(() => bindingValueOf(ctx));
      expectBindingMismatch(() => contextKeyOf(ctx));
    });
  });

  it('`contextKeyOf` / `entryKeyOf` は汚染下でも攻撃者のキー空間へ落ちない', () => {
    const ctx = ctxWithoutBinding('oid4vp');
    withPollutedPrototype({ clientId: ATTACKER_CLIENT }, () => {
      expectBindingMismatch(() => contextKeyOf(ctx));
      expectBindingMismatch(() => entryKeyOf(NONCE, ctx));
    });
  });

  it('`assertBinding` は汚染下でも攻撃者の値を照合対象にしない', () => {
    const ctx = ctxWithoutBinding('oid4vp');
    withPollutedPrototype({ clientId: ATTACKER_CLIENT }, () => {
      // 鎖読みだと汚染値が束縛対象になり、攻撃者の `aud` が「一致」として受理される。
      expectBindingMismatch(() => assertBinding(ctx, ATTACKER_CLIENT));
    });
  });
});

describe('NonceStore#checkAndUse 直接呼び出し / prototype pollution', () => {
  it('束縛値を own に持たない context は汚染下でも 4012 で拒否される', async () => {
    const store = makeStore();
    const ctx = ctxWithoutBinding('oid4vp');
    await withPollutedPrototypeAsync({ clientId: ATTACKER_CLIENT }, async () => {
      try {
        await store.checkAndUse(NONCE, ctx, { binding: ATTACKER_CLIENT });
      } catch (e) {
        expect(e).toBeInstanceOf(VericertsError);
        expect((e as VericertsError).code).toBe(ErrorCodes.NONCE_BINDING_MISMATCH);
        return;
      }
      throw new Error('checkAndUse が汚染下で素通りした（fail-open）');
    });
  });

  it('`flow` を own に持たない context は汚染下でも 4012 で拒否される', async () => {
    const store = makeStore();
    const ctx = { clientId: VICTIM_CLIENT } as unknown as NonceContext;
    await withPollutedPrototypeAsync({ flow: 'oid4vp' }, async () => {
      try {
        await store.checkAndUse(NONCE, ctx, {});
      } catch (e) {
        expect((e as VericertsError).code).toBe(ErrorCodes.NONCE_BINDING_MISMATCH);
        return;
      }
      throw new Error('checkAndUse が汚染下で素通りした（fail-open）');
    });
  });

  it('汚染下でも被害者のキー空間は攻撃者の消費に影響されない', async () => {
    const store = makeStore();
    const victim: NonceContext = { flow: 'oid4vp', clientId: VICTIM_CLIENT };
    // 束縛値を own に持たない context での消費は拒否されるため、被害者の nonce は未消費のまま。
    const attacker = ctxWithoutBinding('oid4vp');
    await withPollutedPrototypeAsync({ clientId: VICTIM_CLIENT }, async () => {
      await expect(store.checkAndUse(NONCE, attacker, {})).rejects.toThrow(VericertsError);
    });
    expect(await store.has(NONCE, victim)).toBe(false);
    // 被害者自身の正当な消費は従来どおり成功する。
    await store.checkAndUse(NONCE, victim, { binding: VICTIM_CLIENT });
    expect(await store.has(NONCE, victim)).toBe(true);
  });

  it('正常系: own の context は汚染下でも従来どおりリプレイを検知する', async () => {
    const store = makeStore();
    const ctx: NonceContext = { flow: 'oid4vp', clientId: VICTIM_CLIENT };
    await withPollutedPrototypeAsync({ clientId: ATTACKER_CLIENT }, async () => {
      await store.checkAndUse(NONCE, ctx, { binding: VICTIM_CLIENT });
      await expect(store.checkAndUse(NONCE, ctx, { binding: VICTIM_CLIENT })).rejects.toThrow(
        VericertsError,
      );
    });
  });
});

describe('checkAndUse のオプション / prototype pollution', () => {
  const CTX: NonceContext = { flow: 'oid4vp', clientId: VICTIM_CLIENT };

  it('`ttlMs` 汚染で初見 nonce を即時失効させられない', async () => {
    const { store, advance } = makeAdvancingStore();
    // 鎖読みだと `opts` の既定値 `{}` が汚染 `ttlMs: 1` を拾い、初見 nonce が 1ms で失効する。
    // prune で消えた後の再提示は「初見」として受理され、リプレイ検知が丸ごとバイパスされる。
    await withPollutedPrototypeAsync({ ttlMs: 1 }, async () => {
      await store.checkAndUse(NONCE, CTX, {});
      advance(1_000);
      await store.prune();
      try {
        await store.checkAndUse(NONCE, CTX, {});
      } catch (e) {
        expect((e as VericertsError).code).toBe(ErrorCodes.REPLAY_DETECTED);
        return;
      }
      throw new Error('汚染 ttlMs で同一 nonce の再消費が受理された（fail-open）');
    });
  });

  it('`one-time-credential` の TTL 必須（RangeError）は `ttlMs` 汚染で素通りしない', async () => {
    const store = makeStore();
    const ctx: NonceContext = { flow: 'one-time-credential', issuer: 'https://issuer.example' };
    // TTL は呼び出し側が指定する。未指定の場合に暗黙の既定値を使わない。
    await withPollutedPrototypeAsync({ ttlMs: 1 }, async () => {
      await expect(store.checkAndUse(NONCE, ctx, {})).rejects.toBeInstanceOf(RangeError);
    });
  });

  it('`one-time-credential` の既定 TTL 表も汚染で埋められない', async () => {
    const store = makeStore();
    const ctx: NonceContext = { flow: 'one-time-credential', issuer: 'https://issuer.example' };
    // `DEFAULT_TTL_MS_BY_FLOW` を鎖読みすると、意図的に**キーを持たせていない**
    // `one-time-credential` に汚染値が入り、RangeError で閉じるはずの経路が 1ms TTL で通る。
    await withPollutedPrototypeAsync({ 'one-time-credential': 1 }, async () => {
      await expect(store.checkAndUse(NONCE, ctx, {})).rejects.toBeInstanceOf(RangeError);
    });
  });

  it('`binding` を省略した正当な呼び出しは `binding` 汚染で拒否されない', async () => {
    const store = makeStore();
    // 鎖読みだと汚染値が「実測 binding」として照合され、正当な提示が一律 4012 で落ちる（DoS）。
    await withPollutedPrototypeAsync({ binding: ATTACKER_CLIENT }, async () => {
      await store.checkAndUse(NONCE, CTX, {});
    });
    expect(await store.has(NONCE, CTX)).toBe(true);
  });

  it('正常系: own の `ttlMs` / `binding` は従来どおり効く', async () => {
    const { store, advance } = makeAdvancingStore();
    await store.checkAndUse(NONCE, CTX, { binding: VICTIM_CLIENT, ttlMs: 1_000 });
    expect(await store.has(NONCE, CTX)).toBe(true);
    advance(2_000);
    expect(await store.has(NONCE, CTX)).toBe(false);
  });
});
