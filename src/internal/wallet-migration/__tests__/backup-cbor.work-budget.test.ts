/**
 * CBOR バックアップ復元の仕事量予算（共有参照 / byte string / 極小コンテナ多数）。
 *
 * 旧実装は復号前検査が見る項目だけ個別に塞いでおり、検査の外（byte string の `Buffer.toJSON()` 展開、空 map の
 * JSON 往復 + reviver 複製）を毎回迂回された。現在は検査と復元を 1 回の走査に統合し、入力長・総ノード数・
 * 入れ子深さの予算を値の確保前に消費する。ここでは攻撃入力の**形（サイズと件数の比率）を変えて**、実時間ではなく
 * 拒否理由（決定的な例外種別）・確保された map 数（`Object.create` の呼び出し回数）・`cbor-x` 復号器の
 * 呼び出し回数で pin する。
 */

import { describe, expect, it, spyOn } from 'bun:test';
import { Decoder, Encoder } from 'cbor-x';
import { ErrorCodes, VericertsError } from '../../errors.js';
import { deserializeBackupFromCbor } from '../backup-serialize.js';
import {
  BACKUP_CBOR_LIMITS,
  type BackupCborLimits,
  BackupCborRejection,
  type BackupCborRejectReason,
  decodeBoundedCbor,
} from '../cbor/bounded-cbor-decode.js';

const TINY: BackupCborLimits = { maxBytes: 4096, maxNodes: 100, maxDepth: 4 };

/** 配列ヘッダ（件数 `count`）を u32 で符号化する。 */
function arrayHead(count: number): number[] {
  return [0x9a, (count >>> 24) & 255, (count >>> 16) & 255, (count >>> 8) & 255, count & 255];
}

/** `item` を `count` 個並べた配列。 */
function repeated(count: number, item: number[]): Uint8Array {
  const out = new Uint8Array(5 + count * item.length);
  out.set(arrayHead(count));
  for (let i = 0; i < count; i++) {
    out.set(item, 5 + i * item.length);
  }
  return out;
}

/** byte string（0x5a + u32 長）。`filled` が偽なら本体なし（宣言だけ）。 */
function byteString(length: number, filled: boolean): Uint8Array {
  const head = [
    0x5a,
    (length >>> 24) & 255,
    (length >>> 16) & 255,
    (length >>> 8) & 255,
    length & 255,
  ];
  const out = new Uint8Array(filled ? 5 + length : 5);
  out.set(head);
  return out;
}

/** tag 28([]) の後ろに、各段が前段を 2 回参照する tag 28([tag 29(i-1), tag 29(i-1)]) を `levels` 段並べた配列。 */
function sharedRefBomb(levels: number): Uint8Array {
  const items: number[][] = [[0xd8, 0x1c, 0x80]];
  for (let i = 1; i < levels; i++) {
    items.push([0xd8, 0x1c, 0x82, 0xd8, 0x1d, i - 1, 0xd8, 0x1d, i - 1]);
  }
  return Uint8Array.from([0x98, levels, ...items.flat()]);
}

/** `depth` 段の `[[[…0…]]]`。 */
function nest(depth: number): Uint8Array {
  return Uint8Array.from([...Array.from({ length: depth }, () => 0x81), 0x00]);
}

function rejectionOf(fn: () => unknown): BackupCborRejectReason {
  try {
    fn();
  } catch (error) {
    if (error instanceof BackupCborRejection) {
      return error.reason;
    }
    throw error;
  }
  throw new Error('rejection expected');
}

/** 復元で確保された map（`Object.create(null)`）の個数を数えながら `fn` を実行する。 */
function countMaps(fn: () => void): number {
  const create = spyOn(Object, 'create');
  try {
    fn();
    return create.mock.calls.filter(([proto]) => proto === null).length;
  } finally {
    create.mockRestore();
  }
}

describe('decodeBoundedCbor: 攻撃入力の形ごとの拒否（決定的カウンタ）', () => {
  it.each([
    ['巨大 byte string（本体あり 1MiB）', byteString(1024 * 1024, true), 'unsupported-type'],
    [
      '巨大 byte string（宣言 4GiB-1・本体なし）',
      byteString(0xffffffff, false),
      'unsupported-type',
    ],
    ['極小 byte string の配列', repeated(2000, [0x41, 0xff]), 'unsupported-type'],
    ['共有参照 DAG（tag 28/29）', sharedRefBomb(24), 'unsupported-type'],
    ['tag（日時 tag 0）', Uint8Array.of(0xc0, 0x61, 0x61), 'unsupported-type'],
  ] as const)('%s は byte string / tag / 不定長として拒否する', (_label, bytes, reason) => {
    expect(rejectionOf(() => decodeBoundedCbor(bytes))).toBe(reason);
  });

  it('byte string は本体の大きさに関係なく head の時点で拒否する（Buffer を作らない）', () => {
    const from = spyOn(Buffer, 'from');
    try {
      for (const length of [1, 1024, 8 * 1024 * 1024]) {
        expect(rejectionOf(() => decodeBoundedCbor(byteString(length, true)))).toBe(
          'unsupported-type',
        );
      }
      expect(from.mock.calls.length).toBe(0);
    } finally {
      from.mockRestore();
    }
  });

  it.each([
    ['少数の巨大な宣言（配列 1M 件・本体なし）', Uint8Array.from(arrayHead(1_000_000))],
    ['極小コンテナ 1M 個（空 map）', repeated(1_000_000, [0xa0])],
    ['極小コンテナ 1M 個（空配列）', repeated(1_000_000, [0x80])],
  ])('%s は既定予算の総ノード数で、map を 1 個も確保せず拒否する', (_label, bytes) => {
    const maps = countMaps(() => {
      expect(rejectionOf(() => decodeBoundedCbor(bytes))).toMatch(/^(too-many-nodes|malformed)$/);
    });
    expect(maps).toBe(0);
  });

  it.each([
    ['空 map の配列', repeated(1000, [0xa0])],
    ['1 エントリ map の配列', repeated(400, [0xa1, 0x61, 0x61, 0x00])],
    ['整数の配列', repeated(1000, [0x00])],
  ])('小さな予算では %s のノード数超過を、予算を超えた時点で拒否する', (_label, bytes) => {
    const maps = countMaps(() => {
      expect(rejectionOf(() => decodeBoundedCbor(bytes, TINY))).toBe('too-many-nodes');
    });
    // 配列の宣言件数が最初に計上されるので、要素を 1 個も作らずに止まる。
    expect(maps).toBe(0);
  });

  it('予算ちょうどは受理し、1 ノード超えると拒否する（境界）', () => {
    // 配列 (1) + 整数 99 個 = 100 ノード。
    const fits = repeated(TINY.maxNodes - 1, [0x00]);
    expect(decodeBoundedCbor(fits, TINY)).toHaveLength(TINY.maxNodes - 1);
    expect(rejectionOf(() => decodeBoundedCbor(repeated(TINY.maxNodes, [0x00]), TINY))).toBe(
      'too-many-nodes',
    );
  });

  it('map のキーと値は別々に計上する（1 エントリ = 2 ノード）', () => {
    const entries = (n: number): Uint8Array =>
      Uint8Array.from([
        0xb9,
        0x00,
        n,
        ...Array.from({ length: n }, (_, i) => [0x61, 0x41 + (i % 26), 0x00]).flat(),
      ]);
    // キーは 1 文字ずつ重複するが後勝ちで良い。ノード数は 1 + 2n。
    expect(() => decodeBoundedCbor(entries(49), TINY)).not.toThrow(); // 99 ノード
    expect(rejectionOf(() => decodeBoundedCbor(entries(50), TINY))).toBe('too-many-nodes'); // 101
  });

  it('入力長の上限を超えるものは中身を見ずに拒否する', () => {
    const oversized = new Uint8Array(TINY.maxBytes + 1);
    const maps = countMaps(() => {
      expect(rejectionOf(() => decodeBoundedCbor(oversized, TINY))).toBe('input-too-long');
    });
    expect(maps).toBe(0);
    expect(BACKUP_CBOR_LIMITS.maxBytes).toBeGreaterThan(0);
  });

  it('入れ子は maxDepth 段まで受理し、超えると拒否する（既定は 32 段）', () => {
    const depth = BACKUP_CBOR_LIMITS.maxDepth;
    expect(() => decodeBoundedCbor(nest(depth))).not.toThrow();
    expect(rejectionOf(() => decodeBoundedCbor(nest(depth + 1)))).toBe('too-deep');
    // 段数を増やしても、拒否までに走査する深さは maxDepth で頭打ち（再帰の暴走がない）。
    expect(rejectionOf(() => decodeBoundedCbor(nest(100_000)))).toBe('too-deep');
  });

  it.each([
    ['長さが残りバイト数を超える文字列', Uint8Array.of(0x79, 0xff, 0xff, 0x61)],
    ['要素数が残りバイト数を超える配列', Uint8Array.of(0x9b, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff)],
    ['末尾の余剰バイト', Uint8Array.of(0x01, 0x02)],
    ['途中で途切れた配列', Uint8Array.of(0x82, 0x01)],
    ['不定長配列', Uint8Array.of(0x9f, 0x01, 0xff)],
    ['空入力', new Uint8Array(0)],
    ['不正な UTF-8', Uint8Array.of(0x62, 0xc3, 0x28)],
  ])('%s は malformed として拒否する', (_label, bytes) => {
    expect(rejectionOf(() => decodeBoundedCbor(bytes))).toBe('malformed');
  });

  it.each([
    ['NaN（float16）', Uint8Array.of(0xf9, 0x7e, 0x00)],
    ['Infinity（float32）', Uint8Array.of(0xfa, 0x7f, 0x80, 0x00, 0x00)],
    ['-Infinity（float64）', Uint8Array.of(0xfb, 0xff, 0xf0, 0, 0, 0, 0, 0, 0)],
    ['非 text キーの map', Uint8Array.of(0xa1, 0x01, 0x02)],
    ['未対応の simple value（simple(16)）', Uint8Array.of(0xf0)],
  ])('%s は unsupported-type として拒否する', (_label, bytes) => {
    expect(rejectionOf(() => decodeBoundedCbor(bytes))).toBe('unsupported-type');
  });
});

describe('deserializeBackupFromCbor: 公開境界での拒否', () => {
  it.each([
    ['巨大 byte string', byteString(8 * 1024 * 1024, true)],
    ['宣言だけ巨大な byte string', byteString(0xffffffff, false)],
    ['極小コンテナ（空 map）1M 個', repeated(1_000_000, [0xa0])],
    ['極小 byte string の配列', repeated(100_000, [0x41, 0xff])],
    ['入れ子 100000 段', nest(100_000)],
    ['共有参照 DAG', sharedRefBomb(24)],
  ])('%s は cbor-x の復号器へ渡らず W2W_INTEGRITY_BROKEN で拒否する', (_label, bytes) => {
    const decode = spyOn(Decoder.prototype, 'decode');
    const decodeEncoder = spyOn(Encoder.prototype, 'decode');
    const maps = countMaps(() => {
      try {
        expect(() => deserializeBackupFromCbor(bytes)).toThrow(
          new VericertsError(ErrorCodes.W2W_INTEGRITY_BROKEN),
        );
        expect(decode.mock.calls.length + decodeEncoder.mock.calls.length).toBe(0);
      } finally {
        decode.mockRestore();
        decodeEncoder.mockRestore();
      }
    });
    expect(maps).toBe(0);
  });
});
