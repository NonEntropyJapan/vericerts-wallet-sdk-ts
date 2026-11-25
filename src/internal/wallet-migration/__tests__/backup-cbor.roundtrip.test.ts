/**
 * CBOR バックアップ復元（`decodeBoundedCbor`）の正常系: 通常のバックアップの往復が壊れないこと
 * （仕事量予算の導入で、正規の `WalletBackup` を拒否しない / JSON 往復と同じ値になる）。
 */

import { describe, expect, it } from 'bun:test';
import { deserializeBackupFromCbor, serializeBackupToCbor } from '../backup-serialize.js';
import { decodeBoundedCbor } from '../cbor/bounded-cbor-decode.js';
import type { WalletBackup } from '../types.js';

describe('正常なバックアップの往復', () => {
  it('serializeBackupToCbor の出力（文字列 / 整数 / 浮動小数 / bool / null）を復元する', () => {
    const backup = {
      version: '1',
      credentials: [{ id: 'vc-1', format: 'dc+sd-jwt', data: 'x'.repeat(300), 日本語: '値' }],
      n: [
        1,
        -2,
        300,
        70_000,
        5_000_000_000,
        1.5,
        -0.25,
        1e21,
        Number.MAX_SAFE_INTEGER,
        true,
        false,
        null,
      ],
      empty: { a: [], b: {} },
    } as unknown as WalletBackup;
    const restored = decodeBoundedCbor(serializeBackupToCbor(backup));
    expect(restored).toEqual(JSON.parse(JSON.stringify(backup)) as unknown);
  });

  it('undefined のフィールドは JSON 往復と同じく存在しない扱いになる', () => {
    const backup = {
      version: '1',
      encryption: {},
      credentials: [],
      personas: [],
      dids: [],
      settings: {},
      integrity: {},
      extra: undefined,
    } as unknown as WalletBackup;
    const restored = deserializeBackupFromCbor(serializeBackupToCbor(backup)) as unknown as Record<
      string,
      unknown
    >;
    expect(Object.hasOwn(restored, 'extra')).toBe(false);
  });

  it('float16 / float32 / float64 の各符号化を復元する', () => {
    const decode = (...bytes: number[]): unknown => decodeBoundedCbor(Uint8Array.from(bytes));
    expect(decode(0xf9, 0x3c, 0x00)).toBe(1);
    expect(decode(0xf9, 0xc4, 0x00)).toBe(-4);
    expect(decode(0xf9, 0x00, 0x01)).toBe(2 ** -24);
    expect(decode(0xf9, 0x7b, 0xff)).toBe(65504);
    expect(decode(0xfa, 0x47, 0xc3, 0x50, 0x00)).toBe(100000);
    expect(decode(0xfb, 0x3f, 0xf1, 0x99, 0x99, 0x99, 0x99, 0x99, 0x9a)).toBe(1.1);
    expect(Object.is(decode(0xf9, 0x80, 0x00), 0)).toBe(true);
  });

  it('既定予算の範囲内の大きなバックアップ（多数のクレデンシャル）を復元する', () => {
    const credentials = Array.from({ length: 5000 }, (_, i) => ({
      id: `vc-${i}`,
      format: 'dc+sd-jwt',
      data: `eyJ${'a'.repeat(200)}${i}`,
    }));
    const backup = {
      version: '1',
      encryption: {},
      credentials,
      personas: [],
      dids: [],
      settings: {},
      integrity: {},
    } as unknown as WalletBackup;
    const restored = deserializeBackupFromCbor(serializeBackupToCbor(backup)) as unknown as {
      credentials: unknown[];
    };
    expect(restored.credentials).toHaveLength(5000);
  });

  it('復元した map は Object.prototype を継承しない（入れ子も）', () => {
    const restored = decodeBoundedCbor(
      Uint8Array.of(
        0xa1,
        0x61,
        0x61,
        0xa1,
        0x69,
        0x5f,
        0x5f,
        0x70,
        0x72,
        0x6f,
        0x74,
        0x6f,
        0x5f,
        0x5f,
        0x01,
      ),
    ) as Record<string, Record<string, unknown>>;
    expect(Object.getPrototypeOf(restored)).toBeNull();
    const inner = restored.a as Record<string, unknown>;
    expect(Object.getPrototypeOf(inner)).toBeNull();
    expect(Object.hasOwn(inner, '__proto__')).toBe(true);
  });
});
