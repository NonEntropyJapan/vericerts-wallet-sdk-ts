/**
 * W3C Bitstring Status List のビット列（`BitstringStatusList`）のユニットテスト（実処理・モック無し）。
 *
 * 検証内容:
 * - W3C §3.1 のビット詰め（先頭エントリは byte 0 の最上位ビット。複数ビットは MSB 先頭）。
 * - 生成時の最小長（131,072 ビット）・用途と `statusSize` の組・値域の拒否（3002）。
 * - `encodedList`（`u` + base64url(GZIP)）の往復と、不正入力（接頭辞なし / base64url / GZIP / 空）の拒否。
 * - 検証側（`decode`）の最小長検査（W3C §3.2 `STATUS_LIST_LENGTH_ERROR` = 3002）。
 */

import { describe, expect, it } from 'bun:test';
import { gzipSync } from 'node:zlib';
import { base64urlnopad } from '@scure/base';
import { type ErrorCode, ErrorCodes, VericertsError } from '../../../errors.js';
import { BitstringStatusList, MIN_BITSTRING_STATUS_LIST_BITS } from '../list.js';

const MIN_BYTES = MIN_BITSTRING_STATUS_LIST_BITS / 8;

function expectCode(fn: () => unknown, code: ErrorCode): void {
  try {
    fn();
  } catch (e) {
    expect(e).toBeInstanceOf(VericertsError);
    expect((e as VericertsError).code).toBe(code);
    return;
  }
  throw new Error('expected throw');
}

async function expectRejectCode(p: Promise<unknown>, code: ErrorCode): Promise<void> {
  const error = await p.then(
    () => undefined,
    (e: unknown) => e,
  );
  expect(error).toBeInstanceOf(VericertsError);
  expect((error as VericertsError).code).toBe(code);
}

/** 生バイト列から `encodedList` を作る（SDK の符号化に依存せず Node の gzip で作る）。 */
function encodedFrom(bytes: Uint8Array): string {
  return `u${base64urlnopad.encode(gzipSync(bytes))}`;
}

describe('BitstringStatusList.create / get / set', () => {
  it('index 0 は byte 0 の最上位ビット（W3C §3.1 の MSB 先頭）', async () => {
    const list = BitstringStatusList.create('revocation', 1, MIN_BITSTRING_STATUS_LIST_BITS);
    list.set(0, 1);
    list.set(9, 1);

    const decoded = await BitstringStatusList.decode(await list.encode(), 'revocation');
    // byte0 = 0b1000_0000, byte1 = 0b0100_0000 を Node の gzip で作った別経路でも同じ読みになる。
    const raw = new Uint8Array(MIN_BYTES);
    raw[0] = 0b1000_0000;
    raw[1] = 0b0100_0000;
    const viaNode = await BitstringStatusList.decode(encodedFrom(raw), 'revocation');
    for (const l of [decoded, viaNode]) {
      expect(l.get(0)).toBe(1);
      expect(l.get(1)).toBe(0);
      expect(l.get(9)).toBe(1);
      expect(l.get(8)).toBe(0);
    }
  });

  it('statusSize=2 のエントリは MSB 先頭の 2 ビット整数で、隣接エントリへ干渉しない', () => {
    const list = BitstringStatusList.create('message', 2, 65_536);
    list.set(7, 2);
    list.set(8, 1);
    list.set(6, 3);
    expect(list.get(6)).toBe(3);
    expect(list.get(7)).toBe(2);
    expect(list.get(8)).toBe(1);
    list.set(7, 0);
    expect(list.get(6)).toBe(3);
    expect(list.get(7)).toBe(0);
    expect(list.get(8)).toBe(1);
  });

  it('statusSize=8 で 0..255 を保持する', () => {
    const list = BitstringStatusList.create('message', 8, 16_384);
    list.set(5, 255);
    list.set(6, 170);
    expect(list.get(5)).toBe(255);
    expect(list.get(6)).toBe(170);
  });

  it('範囲外 index・値域外 value・非整数は 3002', () => {
    const list = BitstringStatusList.create('message', 2, 65_536);
    expectCode(() => list.get(65_536), ErrorCodes.VC_SCHEMA_INVALID);
    expectCode(() => list.get(-1), ErrorCodes.VC_SCHEMA_INVALID);
    expectCode(() => list.get(1.5), ErrorCodes.VC_SCHEMA_INVALID);
    expectCode(() => list.set(0, 4), ErrorCodes.VC_SCHEMA_INVALID);
    expectCode(() => list.set(0, -1), ErrorCodes.VC_SCHEMA_INVALID);
    expectCode(() => list.set(0, 0.5), ErrorCodes.VC_SCHEMA_INVALID);
  });

  it.each([
    ['最小長未満（ビット列 16 KiB 未満）', 'revocation', 1, MIN_BITSTRING_STATUS_LIST_BITS - 1],
    ['message でも最小長未満', 'message', 2, 65_535],
    ['revocation で statusSize 2', 'revocation', 2, 65_536],
    ['suspension で statusSize 2', 'suspension', 2, 65_536],
    ['statusSize 0', 'message', 0, 200_000],
    ['statusSize 9', 'message', 9, 200_000],
    ['length 0', 'revocation', 1, 0],
    ['length が整数でない', 'revocation', 1, 131_072.5],
    ['展開後 8 MiB 超過', 'revocation', 1, 8 * 1024 * 1024 * 8 + 1],
    ['未知の用途', 'refresh', 1, MIN_BITSTRING_STATUS_LIST_BITS],
  ] as const)('create は %s を 3002 で拒否する', (_label, purpose, size, length) => {
    expectCode(
      () => BitstringStatusList.create(purpose as 'revocation', size, length),
      ErrorCodes.VC_SCHEMA_INVALID,
    );
  });

  it('ちょうど最小長（131,072 ビット）は受理する', () => {
    expect(BitstringStatusList.create('revocation', 1, 131_072).length).toBe(131_072);
    expect(BitstringStatusList.create('message', 2, 65_536).length).toBe(65_536);
  });
});

describe('BitstringStatusList.encode / decode', () => {
  it('encode は multibase base64url（u 接頭辞・パディングなし）で、decode で往復する', async () => {
    const list = BitstringStatusList.create('suspension', 1, 131_072);
    list.set(131_071, 1);
    list.set(0, 1);

    const encoded = await list.encode();
    const decoded = await BitstringStatusList.decode(encoded, 'suspension');

    expect(encoded.startsWith('u')).toBe(true);
    expect(encoded).not.toContain('=');
    expect(decoded.purpose).toBe('suspension');
    expect(decoded.length).toBe(131_072);
    expect(decoded.get(0)).toBe(1);
    expect(decoded.get(131_071)).toBe(1);
    expect(decoded.get(1)).toBe(0);
  });

  it('message リストの statusSize は decode へ渡した値でエントリ数が決まる', async () => {
    const list = BitstringStatusList.create('message', 2, 65_536);
    list.set(65_535, 3);

    const decoded = await BitstringStatusList.decode(await list.encode(), 'message', 2);

    expect(decoded.statusSize).toBe(2);
    expect(decoded.length).toBe(65_536);
    expect(decoded.get(65_535)).toBe(3);
  });

  it('最小長（131,072 ビット）未満のリストは STATUS_LIST_LENGTH_ERROR（3002）で拒否する', async () => {
    await expectRejectCode(
      BitstringStatusList.decode(encodedFrom(new Uint8Array(MIN_BYTES - 1)), 'revocation'),
      ErrorCodes.VC_SCHEMA_INVALID,
    );
    await expectRejectCode(
      BitstringStatusList.decode(encodedFrom(new Uint8Array(1)), 'revocation'),
      ErrorCodes.VC_SCHEMA_INVALID,
    );
  });

  it('ちょうど最小長のリストは受理する', async () => {
    const list = await BitstringStatusList.decode(
      encodedFrom(new Uint8Array(MIN_BYTES)),
      'revocation',
    );
    expect(list.length).toBe(MIN_BITSTRING_STATUS_LIST_BITS);
  });

  it.each([
    ['u 接頭辞なし', () => base64urlnopad.encode(gzipSync(new Uint8Array(MIN_BYTES)))],
    ['base64url として不正', () => 'u***'],
    ['GZIP として不正', () => `u${base64urlnopad.encode(new Uint8Array([1, 2, 3, 4]))}`],
    ['空の展開結果', () => encodedFrom(new Uint8Array(0))],
    ['文字列でない', () => 42 as unknown as string],
  ])('decode は %s を 3002 で拒否する', async (_label, make) => {
    await expectRejectCode(
      BitstringStatusList.decode(make(), 'revocation'),
      ErrorCodes.VC_SCHEMA_INVALID,
    );
  });

  it('展開後が上限（8 MiB）を超える GZIP 爆弾は 3002 で拒否する', async () => {
    const bomb = encodedFrom(new Uint8Array(8 * 1024 * 1024 + 1));
    await expectRejectCode(
      BitstringStatusList.decode(bomb, 'revocation'),
      ErrorCodes.VC_SCHEMA_INVALID,
    );
  });

  it('decode は用途・statusSize の組が不正なら 3002（revocation で statusSize 2 など）', async () => {
    const encoded = encodedFrom(new Uint8Array(MIN_BYTES));
    await expectRejectCode(
      BitstringStatusList.decode(encoded, 'revocation', 2),
      ErrorCodes.VC_SCHEMA_INVALID,
    );
    await expectRejectCode(
      BitstringStatusList.decode(encoded, 'message', 9),
      ErrorCodes.VC_SCHEMA_INVALID,
    );
    await expectRejectCode(
      BitstringStatusList.decode(encoded, 'bogus'),
      ErrorCodes.VC_SCHEMA_INVALID,
    );
    await expectRejectCode(
      BitstringStatusList.decode(encoded, 'message', 1.5),
      ErrorCodes.VC_SCHEMA_INVALID,
    );
  });
});
