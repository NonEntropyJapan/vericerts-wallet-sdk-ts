/**
 * scheduleLendExpiryChecks の intervalMs 検証と tick 重複防止。
 */

import { describe, expect, it } from 'bun:test';
import { scheduleLendExpiryChecks } from '../lend.js';

describe('scheduleLendExpiryChecks intervalMs 検証', () => {
  it.each([
    ['NaN', Number.NaN],
    ['負値', -1],
    ['0', 0],
    ['Infinity', Number.POSITIVE_INFINITY],
    ['タイマー上限超過', 2 ** 31],
    ['文字列', '1000' as unknown as number],
  ])('intervalMs=%s は RangeError で拒否し、スケジューラを起動しない', (_name, intervalMs) => {
    let scheduled = 0;
    expect(() =>
      scheduleLendExpiryChecks(() => [], {
        markRevoked: () => undefined,
        intervalMs,
        schedule: () => {
          scheduled++;
          return () => undefined;
        },
      }),
    ).toThrow(RangeError);
    expect(scheduled).toBe(0);
  });

  it('正の有限な intervalMs はそのままスケジューラへ渡す', () => {
    const seen: number[] = [];
    scheduleLendExpiryChecks(() => [], {
      markRevoked: () => undefined,
      intervalMs: 250,
      schedule: (_task, ms) => {
        seen.push(ms);
        return () => undefined;
      },
    });
    expect(seen).toEqual([250]);
  });

  it('前回の tick が未完了の間は次の tick で getTokens を再実行しない', async () => {
    let task: (() => void) | undefined;
    let release: (() => void) | undefined;
    let getTokensCalls = 0;
    scheduleLendExpiryChecks(
      () => {
        getTokensCalls++;
        return new Promise((resolve) => {
          release = () => resolve([]);
        });
      },
      {
        markRevoked: () => undefined,
        schedule: (t) => {
          task = t;
          return () => undefined;
        },
      },
    );

    task?.();
    task?.();
    task?.();
    expect(getTokensCalls).toBe(1);

    release?.();
    await new Promise((resolve) => setTimeout(resolve, 0));
    task?.();
    expect(getTokensCalls).toBe(2);
  });
});
