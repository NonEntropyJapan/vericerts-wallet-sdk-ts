/**
 * `trackAttempt`（取り直しをまたぐ解決の計上）の単体テスト。
 *
 * 1 回目の課金は残し、2 回目は前の試行の課金分を控除枠にして自分の消費を相殺する。1 つの解決が予算へ課金する合計は
 * `max(1 回目, 2 回目)` で、予算本体には自分の課金しか書かない（差し戻し・スナップショット復元はしない）。
 */

import { describe, expect, it } from 'bun:test';
import { createResolutionWorkBudget } from '../../../resolution-budget.js';
import { trackAttempt } from '../../../resolution-charge.js';

const NONE = { units: 0, body: 0 };

describe('trackAttempt: 控除枠', () => {
  it('前の試行の課金分（控除枠）に収まる消費は予算本体へ課金せず、超えた分だけ課金する', () => {
    const shared = createResolutionWorkBudget(1000, 5000);
    const { view, consumed } = trackAttempt(shared, { units: 300, body: 2000 });

    expect(view.remaining).toBe(1300);
    expect(view.remainingBodyLength).toBe(7000);
    view.remaining -= 200;
    view.remainingBodyLength -= 1500;
    expect(shared.remaining).toBe(1000);
    expect(shared.remainingBodyLength).toBe(5000);

    view.remaining -= 200; // 枠の残り 100 を使い切り、超えた 100 だけ課金
    view.remainingBodyLength -= 1000; // 枠の残り 500 を使い切り、超えた 500 だけ課金
    expect(shared.remaining).toBe(900);
    expect(shared.remainingBodyLength).toBe(4500);
    expect(consumed()).toEqual({ units: 400, body: 2500 });
  });

  it('1 つの解決の課金合計は max(1 回目, 2 回目): 2 回目が安ければ 1 回目の課金が残り、同じなら追加は 0、多ければ超過分だけ増える', () => {
    for (const [first, second, charged] of [
      [500, 100, 500],
      [500, 500, 500],
      [500, 800, 800],
    ] as const) {
      const shared = createResolutionWorkBudget(2000, 10_000);
      shared.remaining -= first; // 1 回目の課金（残っている）
      const { view } = trackAttempt(shared, { units: first, body: 0 });
      view.remaining -= second;
      expect(2000 - shared.remaining).toBe(charged);
    }
  });

  it('枠が無い（prior が 0）なら、予算本体への素通しと同じ', () => {
    const shared = createResolutionWorkBudget(1000, 5000);
    const { view, consumed } = trackAttempt(shared, NONE);
    view.remaining -= 250;
    view.remainingBodyLength -= 400;
    expect(shared.remaining).toBe(750);
    expect(shared.remainingBodyLength).toBe(4600);
    expect(consumed()).toEqual({ units: 250, body: 400 });
  });

  it('枠はどんな消費でも予算本体を負にせず、元の上限を超えさせない（全部使い切っても 0）', () => {
    const shared = createResolutionWorkBudget(1000, 5000);
    shared.remaining -= 600;
    const { view } = trackAttempt(shared, { units: 600, body: 0 });
    view.remaining = 0; // 枠 600 + 本体の残り 400 を全部使う
    expect(shared.remaining).toBe(0);
    view.remaining = 0;
    expect(shared.remaining).toBe(0);
    expect(shared.remaining).toBeGreaterThanOrEqual(0);
    expect(shared.remaining).toBeLessThanOrEqual(1000);
  });

  it('枠は 1 回の試行の中でだけ効き、使い切れば以後は通常どおり課金する（枠を再利用できない）', () => {
    const shared = createResolutionWorkBudget(1000, 5000);
    const prior = { units: 100, body: 0 };
    const { view } = trackAttempt(shared, prior);
    view.remaining -= 100;
    expect(shared.remaining).toBe(1000);
    view.remaining -= 100;
    expect(shared.remaining).toBe(900);
  });

  it('並行する別の解決の消費は変えない（自分の課金だけを予算本体へ書く）', () => {
    const shared = createResolutionWorkBudget(1000, 5000);
    const mine = trackAttempt(shared, { units: 200, body: 0 });
    const peer = trackAttempt(shared, NONE);
    peer.view.remaining -= 300;
    mine.view.remaining -= 150; // 枠の中: 本体は動かない
    expect(shared.remaining).toBe(700);
    peer.view.remaining -= 100;
    mine.view.remaining -= 100; // 枠の残り 50 + 超過 50
    expect(shared.remaining).toBe(550);
    expect(peer.consumed()).toEqual({ units: 400, body: 0 });
    expect(mine.consumed()).toEqual({ units: 250, body: 0 });
  });

  it('本体の残りが他の解決に使い尽くされても、枠の範囲の消費は通り、枠を超える消費は拒否される側（呼び出し元の検査）に倒れる', () => {
    const shared = createResolutionWorkBudget(1000, 5000);
    shared.remaining -= 300; // 自分の 1 回目の課金
    const { view } = trackAttempt(shared, { units: 300, body: 0 });
    shared.remaining = 0; // 他の解決が残りを使い切った
    expect(view.remaining).toBe(300);
    view.remaining -= 300;
    expect(shared.remaining).toBe(0);
    expect(view.remaining).toBe(0);
  });
});
