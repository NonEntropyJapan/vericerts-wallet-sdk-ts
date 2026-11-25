/**
 * `metrics-duration.ts`（duration 系メトリクスの単位検査ヘルパー）自身の健全性テスト。
 *
 * 置き換え前の断言（`expect(histogram?.sum).toBeLessThan(1)`）は負荷下で偽陰性に落ちた一方、
 * ミリ秒の取り違えは確かに検出できていた。置き換え後も**その検出力が保たれている**ことを、
 * 実際の計装を通さない合成値で固定する — 実処理を挟むテストでは「秒で載っているから通った」のか
 * 「たまたま短かったから通った」のかを区別できないためである。
 */

import { describe, expect, it } from 'bun:test';
import { expectRecordedInSeconds, timed } from './metrics-duration.js';

describe('duration の単位検査ヘルパー', () => {
  it('秒で載った値は受理する', () => {
    // 実測 120ms の区間。秒なら 0.12 が載る。
    expect(() => expectRecordedInSeconds(0.12, 120)).not.toThrow();
  });

  it('ミリ秒のまま載った値は拒否する（断言の目的が保たれている）', () => {
    expect(() => expectRecordedInSeconds(120, 120)).toThrow();
  });

  it('負荷で実測が伸びても、秒で載っていれば受理しミリ秒なら拒否する', () => {
    // 単位検査の境界例。旧断言（< 1）はここで落ちていたが、単位としては正しい。
    expect(() => expectRecordedInSeconds(1.67, 1670)).not.toThrow();
    expect(() => expectRecordedInSeconds(1670, 1670)).toThrow();
  });

  it('計装区間より外側が長い場合も、秒なら受理する', () => {
    // 計装区間（記録側）は計測区間に含まれるので、記録値が上限を下回るのは正常である。
    expect(() => expectRecordedInSeconds(0.005, 1200)).not.toThrow();
  });

  it('負の値と系列欠落は拒否する', () => {
    expect(() => expectRecordedInSeconds(-0.1, 120)).toThrow();
    expect(() => expectRecordedInSeconds(undefined, 120)).toThrow();
  });

  it('timed は action の実時間をミリ秒で返す', async () => {
    const sleepMs = 20;
    const elapsedMs = await timed(
      () => new Promise<void>((resolve) => setTimeout(resolve, sleepMs)),
    );

    // 下限は `sleepMs` に紐づける。`>= 0` だけだと**常に 0 を返す壊れた `timed`** でも通り、
    // 「実時間を返す」という断言が失敗し得なくなる。`setTimeout` は指定より早く発火しない規定
    // だが、`Date.now()` の分解能（1ms）ぶんの丸めを見込んで 2ms だけ緩める。
    expect(elapsedMs).toBeGreaterThanOrEqual(sleepMs - 2);
    // 上限は置かない（本ヘルパー自身が「実時間に絶対値の上限を置かない」ための道具である）。
    expect(Number.isFinite(elapsedMs)).toBe(true);
  });
});
