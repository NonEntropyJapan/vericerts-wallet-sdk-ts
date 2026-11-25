/**
 * キー単位の直列化ロック（`KeyLock`）の
 * ユニットテスト（line coverage 71.43% → 90%以上）。
 *
 * 検証内容:
 * - 同一キーへの逐次呼び出しは実行完了ごとに待ち行列（`pendingKeys`）から除去される
 *   （`run` の `finally` 内、待ち行列の最後尾を自分が占めている場合の削除分岐）。
 * - 同一キーへの並行呼び出しは Promise チェーンで直列化され、実行順序が呼び出し順になる。
 *   先着の呼び出しが完了した時点では、後続がまだ待ち行列を占めているため削除分岐を通らない
 *   （＝「自分が最後尾ではない」場合に削除をスキップする分岐）。
 * - 全ての直列化処理が完了すると、待ち行列は空になりリークしない。
 * - 異なるキーは互いにブロックしない。
 * - `fn` が例外を投げても直列化チェーンは継続し、後続の呼び出しは実行され、
 *   投げた本人には元の例外がそのまま伝播する。
 */

import { describe, expect, it } from 'bun:test';
import { KeyLock } from '../key-lock.js';

describe('KeyLock（同一キー直列化ロック）', () => {
  it('逐次呼び出しは完了ごとに待ち行列から除去される（pendingKeys が 0 に戻る）', async () => {
    const lock = new KeyLock();
    expect(lock.pendingKeys).toBe(0);

    const first = await lock.run('k', async () => 1);
    expect(first).toBe(1);
    // 待ち行列の最後尾が自分自身なので削除分岐を通り、リークしない。
    expect(lock.pendingKeys).toBe(0);

    const second = await lock.run('k', async () => 2);
    expect(second).toBe(2);
    expect(lock.pendingKeys).toBe(0);
  });

  it('同一キーの並行呼び出しは実行順序どおりに直列化され、完了後に待ち行列が空になる', async () => {
    const lock = new KeyLock();
    const order: number[] = [];

    const p1 = lock.run('shared', async () => {
      // 1 回目は他方より長く保持し、2 回目の呼び出しが先に待ち行列へ入るようにする。
      await Promise.resolve();
      await Promise.resolve();
      order.push(1);
    });
    // 1 回目がまだ完了していない間に 2 回目を投入する。
    const p2 = lock.run('shared', async () => {
      order.push(2);
    });

    // 2 回目が待ち行列に入った時点で、キーはまだ Map に残っている（最低 1 件）。
    expect(lock.pendingKeys).toBe(1);

    await Promise.all([p1, p2]);

    // 実行順序は呼び出し順（1 → 2）を維持する。
    expect(order).toEqual([1, 2]);
    // 両方完了後は待ち行列から除去され、リークしない。
    expect(lock.pendingKeys).toBe(0);
  });

  it('異なるキーは互いにブロックしない', async () => {
    const order: number[] = [];
    const lock = new KeyLock();

    const slow = lock.run('a', async () => {
      await Promise.resolve();
      await Promise.resolve();
      order.push(1);
    });
    const fast = lock.run('b', async () => {
      order.push(2);
    });

    await Promise.all([slow, fast]);

    // 別キーの `fast` は `slow` を待たずに先に完了する。
    expect(order).toEqual([2, 1]);
    expect(lock.pendingKeys).toBe(0);
  });

  it('fn が例外を投げてもチェーンは継続し、後続の呼び出しは実行され、待ち行列はリークしない', async () => {
    const lock = new KeyLock();
    const order: string[] = [];

    const failing = lock.run('k', async () => {
      order.push('first');
      throw new Error('boom');
    });
    const following = lock.run('k', async () => {
      order.push('second');
      return 'ok';
    });

    await expect(failing).rejects.toThrow('boom');
    await expect(following).resolves.toBe('ok');

    expect(order).toEqual(['first', 'second']);
    expect(lock.pendingKeys).toBe(0);
  });

  it('pendingKeys はキーごとに個別集計される', async () => {
    const lock = new KeyLock();

    const p1 = lock.run('x', async () => {
      await Promise.resolve();
    });
    const p2 = lock.run('y', async () => {
      await Promise.resolve();
    });

    // 異なる 2 キーが同時に待ち行列を占有している。
    expect(lock.pendingKeys).toBe(2);

    await Promise.all([p1, p2]);

    expect(lock.pendingKeys).toBe(0);
  });

  it('tryRun は空きキーなら実行し、処理中・待機中のキーは待たずに ran:false を返す', async () => {
    const lock = new KeyLock();
    const idle = await lock.tryRun('k', async () => 'v');
    expect(idle).toEqual({ ran: true, value: 'v' });
    expect(lock.pendingKeys).toBe(0);

    let release!: () => void;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const holder = lock.run('k', () => gate);
    // 別キーは取れる。使用中の同一キーは待たずに（デッドロックせずに）拒否される。
    expect(await lock.tryRun('other', async () => 1)).toEqual({ ran: true, value: 1 });
    expect(await lock.tryRun('k', async () => 2)).toEqual({ ran: false });
    release();
    await holder;
    expect(await lock.tryRun('k', async () => 3)).toEqual({ ran: true, value: 3 });
    expect(lock.pendingKeys).toBe(0);
  });
});
