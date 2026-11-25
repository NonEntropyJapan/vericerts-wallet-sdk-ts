/**
 * Token Status List のビット列管理と zlib（DEFLATE）圧縮プリミティブ。
 *
 * IETF draft-ietf-oauth-status-list 準拠。
 *
 * Status List Token の `status_list.lst` は `base64url(zlib-compressed(bitstring))`。本モジュールは
 * その素になるビット列（`StatusBitstring`）の読み書きと、Web 標準の `CompressionStream` /
 * `DecompressionStream`（`'deflate'` = RFC 1950 zlib 形式）による圧縮・展開を担う。`pako` 等の
 * 圧縮ライブラリは導入しない（ブラウザ標準で完結させ、bundle / 依存を増やさない）。
 *
 * ビット詰め（draft §4）:
 * - エントリは `bits`（1/2/4/8）ビット幅。1 バイトに `8 / bits` 個のエントリが入る。
 * - インデックス `i` のエントリは byte `floor(i * bits / 8)` 内に、最下位ビット側から詰める
 *   （`shift = (i * bits) % 8`、`value << shift`）。
 *
 * セキュリティ上の注意:
 * - 例外メッセージや `context` に URL・インデックス・ビット値を含めない。
 */

import { base64urlnopad } from '@scure/base';
import { ErrorCodes, VericertsError } from '../errors.js';

/** Status List のエントリあたりビット数（draft §4.1: 1 / 2 / 4 / 8 のいずれか）。 */
export type StatusBits = 1 | 2 | 4 | 8;

/** 許容されるエントリビット幅の集合。 */
const ALLOWED_BITS: ReadonlySet<number> = new Set([1, 2, 4, 8]);

/**
 * Token Status List のビット列。固定容量（エントリ数）で確保し、`bits` 幅でエントリを詰める。
 *
 * インデックスは 0 始まり。`get` / `set` は容量外アクセス・値域外をエラーにする。
 */
export class StatusBitstring {
  /** エントリあたりのビット数。 */
  readonly bits: StatusBits;
  /** 収容可能なエントリ数（容量）。 */
  readonly size: number;
  /** 内部バイト列（`ceil(size * bits / 8)` バイト）。 */
  private readonly bytes: Uint8Array;
  /** 1 エントリで表現できる値の上限（`2^bits - 1`）。 */
  private readonly maxValue: number;

  /**
   * 指定容量・ビット幅で全ビット 0 の Status List を確保する。
   *
   * @param size 収容するエントリ数（> 0）。
   * @param bits エントリあたりのビット数（1 / 2 / 4 / 8）。既定 1。
   * @throws size が正でない / bits が不正な場合（VericertsError、code `3002`）。
   */
  constructor(size: number, bits: StatusBits = 1) {
    if (!Number.isInteger(size) || size <= 0) {
      throw new VericertsError(ErrorCodes.VC_SCHEMA_INVALID);
    }
    if (!ALLOWED_BITS.has(bits)) {
      throw new VericertsError(ErrorCodes.VC_SCHEMA_INVALID);
    }
    this.bits = bits;
    this.size = size;
    this.maxValue = (1 << bits) - 1;
    this.bytes = new Uint8Array(Math.ceil((size * bits) / 8));
  }

  /**
   * 既存のバイト列（展開済み）から Status List を復元する。
   *
   * @param bytes 展開済みのビット列バイト。
   * @param size エントリ数（容量）。
   * @param bits エントリあたりのビット数。
   * @returns 復元した `StatusBitstring`。
   * @throws bytes の長さが size / bits と整合しない場合（VericertsError、code `3002`）。
   */
  static fromBytes(bytes: Uint8Array, size: number, bits: StatusBits = 1): StatusBitstring {
    const list = new StatusBitstring(size, bits);
    if (bytes.length !== list.bytes.length) {
      throw new VericertsError(ErrorCodes.VC_SCHEMA_INVALID);
    }
    list.bytes.set(bytes);
    return list;
  }

  /**
   * インデックス `index` のエントリ値を読み取る。
   *
   * @param index 0 始まりのエントリインデックス。
   * @returns エントリのビット値（0..2^bits-1）。
   * @throws index が容量外の場合（VericertsError、code `3002`）。
   */
  get(index: number): number {
    this.assertIndex(index);
    const bitPos = index * this.bits;
    const bytePos = Math.floor(bitPos / 8);
    const shift = bitPos % 8;
    // assertIndex で容量内が保証されるため bytePos は常に範囲内（?? 0 は型ナローイング用）。
    const byte = this.bytes[bytePos] ?? 0;
    return (byte >> shift) & this.maxValue;
  }

  /**
   * インデックス `index` のエントリ値を設定する。
   *
   * @param index 0 始まりのエントリインデックス。
   * @param value 設定する値（0..2^bits-1）。
   * @throws index が容量外 / value が値域外の場合（VericertsError、code `3002`）。
   */
  set(index: number, value: number): void {
    this.assertIndex(index);
    if (!Number.isInteger(value) || value < 0 || value > this.maxValue) {
      throw new VericertsError(ErrorCodes.VC_SCHEMA_INVALID);
    }
    const bitPos = index * this.bits;
    const bytePos = Math.floor(bitPos / 8);
    const shift = bitPos % 8;
    // 対象エントリのビットをクリアしてから新しい値を OR で書き込む。
    // assertIndex で容量内が保証されるため bytePos は常に範囲内（?? 0 は型ナローイング用）。
    const cleared = (this.bytes[bytePos] ?? 0) & ~(this.maxValue << shift);
    this.bytes[bytePos] = cleared | (value << shift);
  }

  /**
   * 展開済みバイト列のコピーを返す（内部状態は共有しない）。
   *
   * @returns ビット列バイトのコピー。
   */
  toBytes(): Uint8Array {
    return this.bytes.slice();
  }

  /** index の妥当性（整数・容量内）を検証する。 */
  private assertIndex(index: number): void {
    if (!Number.isInteger(index) || index < 0 || index >= this.size) {
      throw new VericertsError(ErrorCodes.VC_SCHEMA_INVALID);
    }
  }
}

/**
 * Web 標準ストリーム（`CompressionStream` / `DecompressionStream`）でバイト列を変換するヘルパ。
 *
 * `CompressionStream` の `writable` は DOM 型上 `WritableStream<BufferSource>` のため、
 * `TransformStream<Uint8Array, Uint8Array>` では型不一致になる。読み書きする pair として
 * 最小限の構造のみを要求する。
 *
 * W3C Bitstring Status List（`bitstring-status-list/list.ts`）が GZIP の圧縮・展開に同じ
 * 上限付きの変換を使えるよう公開している（zlib 専用の実装を 2 本持たない）。
 */
export async function transform(
  data: Uint8Array,
  stream: {
    readonly writable: WritableStream<Uint8Array>;
    readonly readable: ReadableStream<Uint8Array>;
  },
  maxOutputBytes = Number.POSITIVE_INFINITY,
): Promise<Uint8Array> {
  const writer = stream.writable.getWriter();
  const reader = stream.readable.getReader();

  // 入力データを書き込み、ストリームを閉じる。write/close の rejection は read 側でも
  // 表面化するが、未処理 rejection を避けるため明示的に握って read のエラーに委ねる。
  const writePromise = (async () => {
    await writer.write(data);
    await writer.close();
  })().catch(() => {
    /* read 側で同じエラーが表面化するためここでは握る */
  });

  const chunks: Uint8Array[] = [];
  let received = 0;
  for (;;) {
    const { value, done } = await reader.read();
    if (done) {
      break;
    }
    received += value.length;
    if (received > maxOutputBytes) {
      // 展開爆弾（DEFLATE は最大約 1032:1）。これ以上溜めずにストリームを打ち切る。
      await reader.cancel();
      await writePromise;
      throw new RangeError('出力が上限を超えました');
    }
    chunks.push(value);
  }
  await writePromise;

  const total = chunks.reduce((acc, c) => acc + c.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const c of chunks) {
    out.set(c, offset);
    offset += c.length;
  }
  return out;
}

/**
 * ビット列を zlib（DEFLATE / RFC 1950）で圧縮し base64url（パディングなし）へ符号化する。
 *
 * `status_list.lst` の生成に用いる。圧縮には Web 標準 `CompressionStream('deflate')` を使う。
 *
 * @param bytes 展開済みビット列バイト。
 * @returns `base64url(zlib(bytes))`。
 */
export async function compressBitstring(bytes: Uint8Array): Promise<string> {
  // CompressionStream の writable は DOM 型上 WritableStream<BufferSource>。実体は Uint8Array を
  // 受け付けるため、helper が要求する WritableStream<Uint8Array> 形へキャストする。
  const stream = new CompressionStream('deflate') as unknown as {
    writable: WritableStream<Uint8Array>;
    readable: ReadableStream<Uint8Array>;
  };
  const compressed = await transform(bytes, stream);
  return base64urlnopad.encode(compressed);
}

/**
 * 展開後ビット列の最大バイト数（8 MiB = `bits: 1` で約 6,700 万エントリ）。
 *
 * `status_list.lst` は Issuer 由来で、DEFLATE の圧縮比は最大約 1032:1 のため、約 1.3 MiB の
 * `lst` が 1 GiB 超へ展開され得る。実運用の Status List はこれより桁違いに小さい。
 */
export const MAX_DECOMPRESSED_BITSTRING_BYTES = 8 * 1024 * 1024;

/**
 * `lst`（base64url 文字列）の最大長。展開前の早期拒否に使う。
 *
 * 展開後上限の非圧縮データ（DEFLATE の格納ブロックで約 +0.03% の増分）を base64url（4/3 倍）で
 * 表した長さに余裕を持たせた値。
 */
export const MAX_LST_LENGTH = Math.ceil((MAX_DECOMPRESSED_BITSTRING_BYTES * 4) / 3) + 1024;

/**
 * `status_list.lst`（base64url(zlib(bitstring))）を展開してビット列バイトへ復元する。
 *
 * 展開後サイズは {@link MAX_DECOMPRESSED_BITSTRING_BYTES} まで。`lst` の長さも
 * {@link MAX_LST_LENGTH} までで、超過時は展開前 / 展開途中に打ち切る。
 *
 * @param lst `compressBitstring` が生成した base64url 文字列。
 * @returns 展開済みビット列バイト。
 * @throws base64url / zlib として不正、または `lst` / 展開後サイズが上限超過の場合
 *   （VericertsError、code `3002`）。
 */
export async function decompressBitstring(lst: string): Promise<Uint8Array> {
  if (lst.length > MAX_LST_LENGTH) {
    throw new VericertsError(ErrorCodes.VC_SCHEMA_INVALID);
  }
  let compressed: Uint8Array;
  try {
    compressed = base64urlnopad.decode(lst);
  } catch {
    // 入力（lst）は VC 本文に準ずるため値はメッセージに含めず構造不正へ正規化する。
    throw new VericertsError(ErrorCodes.VC_SCHEMA_INVALID);
  }
  const stream = new DecompressionStream('deflate') as unknown as {
    writable: WritableStream<Uint8Array>;
    readable: ReadableStream<Uint8Array>;
  };
  try {
    return await transform(compressed, stream, MAX_DECOMPRESSED_BITSTRING_BYTES);
  } catch {
    throw new VericertsError(ErrorCodes.VC_SCHEMA_INVALID);
  }
}
