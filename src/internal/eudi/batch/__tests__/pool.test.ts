/**
 * Batch Pool 消費追跡・パージテスト。
 */

import { describe, expect, test } from 'bun:test';
import { consumeCredential, countAvailable, purgeExpired } from '../pool.js';
import type { BatchPoolItem } from '../types.js';

const NOW = 1_000_000;

function item(overrides: Partial<BatchPoolItem> & { id: string }): BatchPoolItem {
  return {
    vc: `vc-${overrides.id}`,
    keyHandle: `kp-${overrides.id}`,
    used: false,
    expiresAt: NOW + 60_000,
    ...overrides,
  };
}

describe('countAvailable', () => {
  test('未使用かつ未期限切れの VC のみ数える', () => {
    const pool = [
      item({ id: '1' }),
      item({ id: '2', used: true }),
      item({ id: '3', expiresAt: NOW - 1 }),
      item({ id: '4' }),
    ];
    expect(countAvailable(pool, NOW)).toBe(2);
  });

  test('空プールは 0', () => {
    expect(countAvailable([], NOW)).toBe(0);
  });
});

describe('consumeCredential', () => {
  test('未使用 VC を 1 個だけ消費し used=true に更新する', () => {
    const pool = [item({ id: '1' }), item({ id: '2' })];
    const result = consumeCredential(pool, NOW, 'rp-v1');
    expect(result.consumed).toBe(true);
    expect(result.item?.used).toBe(true);
    expect(result.item?.consumedRp).toBe('rp-v1');
    expect(result.item?.consumedAt).toBe(NOW);
    // 消費したのは 1 個のみ。
    expect(countAvailable(result.pool, NOW)).toBe(1);
  });

  test('最も早く期限切れになる VC を優先消費する（在庫回転）', () => {
    const pool = [
      item({ id: 'late', expiresAt: NOW + 100_000 }),
      item({ id: 'soon', expiresAt: NOW + 10_000 }),
    ];
    const result = consumeCredential(pool, NOW, 'rp');
    expect(result.item?.id).toBe('soon');
  });

  test('入力プールを変更しない（immutable）', () => {
    const pool = [item({ id: '1' })];
    consumeCredential(pool, NOW, 'rp');
    expect(pool[0]?.used).toBe(false);
  });

  test('連続消費で異なる VC（異なる cnf 鍵）を返す — Unlinkability', () => {
    let pool: readonly BatchPoolItem[] = [item({ id: '1' }), item({ id: '2' })];
    const r1 = consumeCredential(pool, NOW, 'rp-v1');
    pool = r1.pool;
    const r2 = consumeCredential(pool, NOW, 'rp-v2');
    expect(r1.item?.keyHandle).not.toBe(r2.item?.keyHandle);
    expect(r1.item?.id).not.toBe(r2.item?.id);
  });

  test('有効な VC が無ければ consumed=false・プール不変', () => {
    const pool = [item({ id: '1', used: true }), item({ id: '2', expiresAt: NOW - 1 })];
    const result = consumeCredential(pool, NOW, 'rp');
    expect(result.consumed).toBe(false);
    expect(result.item).toBeUndefined();
    expect(result.pool).toBe(pool);
  });
});

describe('purgeExpired', () => {
  test('期限切れ VC を除去し鍵ハンドルを返す（境界: expiresAt <= now は期限切れ）', () => {
    const pool = [
      item({ id: 'alive', expiresAt: NOW + 1 }),
      item({ id: 'edge', expiresAt: NOW }),
      item({ id: 'dead', expiresAt: NOW - 1 }),
    ];
    const result = purgeExpired(pool, NOW);
    expect(result.pool.map((i) => i.id)).toEqual(['alive']);
    expect(result.removedKeyHandles).toEqual(['kp-edge', 'kp-dead']);
  });

  test('使用済みでも未期限切れなら残す（パージは期限のみで判定）', () => {
    const pool = [item({ id: '1', used: true, expiresAt: NOW + 1000 })];
    const result = purgeExpired(pool, NOW);
    expect(result.pool).toHaveLength(1);
    expect(result.removedKeyHandles).toHaveLength(0);
  });

  test('入力プールを変更しない（immutable）', () => {
    const pool = [item({ id: '1', expiresAt: NOW - 1 })];
    purgeExpired(pool, NOW);
    expect(pool).toHaveLength(1);
  });
});
