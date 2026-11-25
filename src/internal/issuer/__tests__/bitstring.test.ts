/**
 * Token Status List のビット操作・zlib 圧縮プリミティブのユニットテスト（モック禁止・実処理）。
 *
 * 検証内容:
 * - bits=1/2/4/8 での set/get ラウンドトリップ（隣接エントリへの干渉なし）。
 * - 容量外・値域外・不正 bits/size の拒否（3002）。
 * - compress → decompress でビット列が完全復元される（zlib DEFLATE 往復）。
 * - fromBytes での復元と長さ不整合の拒否。
 * - 不正 lst（base64url / zlib 不正）の拒否（3002）。
 */

import { describe, expect, it } from 'bun:test';
import { type ErrorCode, ErrorCodes, VericertsError } from '../../errors.js';
import {
  compressBitstring,
  decompressBitstring,
  MAX_DECOMPRESSED_BITSTRING_BYTES,
  MAX_LST_LENGTH,
  type StatusBits,
  StatusBitstring,
} from '../bitstring.js';

/** VericertsError かつ指定コードであることを検証する。 */
function expectError(fn: () => unknown, code: ErrorCode): void {
  try {
    fn();
  } catch (e) {
    expect(e).toBeInstanceOf(VericertsError);
    expect((e as VericertsError).code).toBe(code);
    return;
  }
  throw new Error('expected throw');
}

describe('StatusBitstring', () => {
  it('bits=1 で set/get がラウンドトリップする', () => {
    const list = new StatusBitstring(16, 1);
    expect(list.get(0)).toBe(0);
    list.set(3, 1);
    list.set(10, 1);
    expect(list.get(3)).toBe(1);
    expect(list.get(10)).toBe(1);
    expect(list.get(4)).toBe(0);
    expect(list.get(9)).toBe(0);
  });

  it('set で 1 にしたビットを 0 に戻せる（隣接へ干渉しない）', () => {
    const list = new StatusBitstring(8, 1);
    list.set(0, 1);
    list.set(1, 1);
    list.set(2, 1);
    list.set(1, 0);
    expect(list.get(0)).toBe(1);
    expect(list.get(1)).toBe(0);
    expect(list.get(2)).toBe(1);
  });

  it.each([2, 4, 8] as StatusBits[])('bits=%d で複数値を独立に保持する', (bits) => {
    const list = new StatusBitstring(20, bits);
    const max = (1 << bits) - 1;
    list.set(0, 1);
    list.set(1, max);
    list.set(2, 0);
    list.set(3, max > 1 ? max - 1 : 1);
    expect(list.get(0)).toBe(1);
    expect(list.get(1)).toBe(max);
    expect(list.get(2)).toBe(0);
    expect(list.get(3)).toBe(max > 1 ? max - 1 : 1);
  });

  it('容量外インデックスの get/set を 3002 で拒否する', () => {
    const list = new StatusBitstring(8, 1);
    expectError(() => list.get(8), ErrorCodes.VC_SCHEMA_INVALID);
    expectError(() => list.set(8, 1), ErrorCodes.VC_SCHEMA_INVALID);
    expectError(() => list.get(-1), ErrorCodes.VC_SCHEMA_INVALID);
  });

  it('値域外の値を 3002 で拒否する', () => {
    const list = new StatusBitstring(8, 1);
    expectError(() => list.set(0, 2), ErrorCodes.VC_SCHEMA_INVALID);
    const list2 = new StatusBitstring(8, 2);
    expectError(() => list2.set(0, 4), ErrorCodes.VC_SCHEMA_INVALID);
  });

  it('不正な size / bits を 3002 で拒否する', () => {
    expectError(() => new StatusBitstring(0, 1), ErrorCodes.VC_SCHEMA_INVALID);
    expectError(() => new StatusBitstring(-1, 1), ErrorCodes.VC_SCHEMA_INVALID);
    // 3 は許容外のビット幅。
    expectError(() => new StatusBitstring(8, 3 as StatusBits), ErrorCodes.VC_SCHEMA_INVALID);
  });

  it('fromBytes で復元し、長さ不整合を 3002 で拒否する', () => {
    const list = new StatusBitstring(16, 1);
    list.set(5, 1);
    const restored = StatusBitstring.fromBytes(list.toBytes(), 16, 1);
    expect(restored.get(5)).toBe(1);
    expectError(
      () => StatusBitstring.fromBytes(new Uint8Array(1), 16, 1),
      ErrorCodes.VC_SCHEMA_INVALID,
    );
  });

  it('toBytes は内部状態を共有しない（防御的コピー）', () => {
    const list = new StatusBitstring(8, 1);
    list.set(0, 1);
    const bytes = list.toBytes();
    bytes[0] = 0;
    expect(list.get(0)).toBe(1);
  });
});

describe('compress/decompress', () => {
  it('zlib 往復でビット列が完全復元される', async () => {
    const list = new StatusBitstring(1000, 1);
    list.set(0, 1);
    list.set(42, 1);
    list.set(999, 1);
    const lst = await compressBitstring(list.toBytes());
    const restored = StatusBitstring.fromBytes(await decompressBitstring(lst), 1000, 1);
    expect(restored.get(0)).toBe(1);
    expect(restored.get(42)).toBe(1);
    expect(restored.get(999)).toBe(1);
    expect(restored.get(1)).toBe(0);
  });

  it('全 0 のビット列も往復できる', async () => {
    const list = new StatusBitstring(256, 2);
    const lst = await compressBitstring(list.toBytes());
    const bytes = await decompressBitstring(lst);
    expect(Array.from(bytes).every((b) => b === 0)).toBe(true);
  });

  it('不正な lst を 3002 で拒否する', async () => {
    await expect(decompressBitstring('!!!not-base64url!!!')).rejects.toMatchObject({
      code: ErrorCodes.VC_SCHEMA_INVALID,
    });
    // 妥当な base64url だが zlib として不正なバイト列。
    await expect(decompressBitstring('AAAAAAAA')).rejects.toMatchObject({
      code: ErrorCodes.VC_SCHEMA_INVALID,
    });
  });

  describe('展開サイズの上限', () => {
    it('上限ちょうどのビット列は展開できる', async () => {
      const lst = await compressBitstring(new Uint8Array(MAX_DECOMPRESSED_BITSTRING_BYTES));
      const bytes = await decompressBitstring(lst);
      expect(bytes.length).toBe(MAX_DECOMPRESSED_BITSTRING_BYTES);
    });

    it('展開後が上限を超える小さな lst（展開爆弾）を 3002 で拒否する', async () => {
      const lst = await compressBitstring(new Uint8Array(MAX_DECOMPRESSED_BITSTRING_BYTES + 1));
      expect(lst.length).toBeLessThan(MAX_LST_LENGTH);
      await expect(decompressBitstring(lst)).rejects.toMatchObject({
        code: ErrorCodes.VC_SCHEMA_INVALID,
      });
    });

    it('lst の文字列長が上限を超えると展開前に 3002 で拒否する', async () => {
      await expect(decompressBitstring('A'.repeat(MAX_LST_LENGTH + 1))).rejects.toMatchObject({
        code: ErrorCodes.VC_SCHEMA_INVALID,
      });
    });
  });
});
