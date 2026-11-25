/**
 * W3C Bitstring Status List v1.0 のビット列（`BitstringStatusList`）と `encodedList` の符号化。
 *
 * W3C
 * <https://www.w3.org/TR/vc-bitstring-status-list/> §2.2 BitstringStatusList / §3.1 Bitstring
 * Generation / §3.2 Validate Algorithm。
 *
 * IETF Token Status List（`../bitstring.ts` の `StatusBitstring`）とは**ビット詰めが逆**である:
 *
 * - Token Status List（draft §4）: エントリは byte 内で最下位ビット側から詰める。
 * - Bitstring Status List（W3C §3.1）: 先頭エントリは byte 0 の**最上位ビット**。`statusSize` ビットの
 *   エントリはビット位置 `index * statusSize` から最上位ビット側を先頭に連続して並ぶ。
 *
 * 取り違えると別エントリのビットを読むため（失効の取りこぼし）、`StatusBitstring` を流用せず
 * 別クラスにしている。`encodedList` は multibase base64url（先頭 `u`、パディングなし）+ GZIP。
 *
 * 最小長（herd privacy）: リストは非圧縮で 131,072 ビット（16 KiB）以上でなければならない
 * （W3C §3.2 の `minimumNumberOfEntries` = 131,072）。生成側は強制し、検証側（`decode`）も
 * 満たさないリストを `STATUS_LIST_LENGTH_ERROR`（W3C）= `VC_SCHEMA_INVALID`（3002）で拒否する。
 *
 * セキュリティ上の注意:
 * - 例外メッセージや `context` に URL・インデックス・ビット値・JWT を含めない。
 */

import { base64urlnopad } from '@scure/base';
import { ErrorCodes, VericertsError } from '../../errors.js';
import { MAX_DECOMPRESSED_BITSTRING_BYTES, transform } from '../bitstring.js';

/** Bitstring Status List の用途（W3C §2.1 `statusPurpose`）。 */
export type BitstringStatusPurpose = 'revocation' | 'suspension' | 'message';

/**
 * 非圧縮ビット列の最小長（ビット）。W3C §3.2 の `minimumNumberOfEntries`（131,072）。
 *
 * `statusSize` が 1 より大きい場合の扱い: W3C は「ビット列長 ÷ `statusSize` < 最小エントリ数」と
 * 書くが、`message` 目的のリストをビット列 16 KiB 未満では作れなくなる（Go 実装・共有 ext ベクタは
 * 16 KiB = 65,536 エントリ × 2 ビットの message リストを有効とする）。ここでは Go 実装の生成規則
 * （`length * statusSize >= 131,072`）に揃え、**非圧縮ビット列が 16 KiB 以上**を最小長とする。
 */
export const MIN_BITSTRING_STATUS_LIST_BITS = 131_072;

/** `statusSize`（1 エントリのビット数）の上限（Go 実装と同じ。W3C に上限の規定は無い）。 */
export const MAX_BITSTRING_STATUS_SIZE = 8;

/** `encodedList` の multibase 接頭辞（base64url、パディングなし）。 */
const MULTIBASE_BASE64URL = 'u';

/** `encodedList` の最大長。展開前の早期拒否に使う（展開後上限の GZIP 格納 + base64url）。 */
const MAX_ENCODED_LIST_LENGTH = Math.ceil((MAX_DECOMPRESSED_BITSTRING_BYTES * 4) / 3) + 1024;

const invalid = (): VericertsError => new VericertsError(ErrorCodes.VC_SCHEMA_INVALID);

function isPurpose(value: unknown): value is BitstringStatusPurpose {
  return value === 'revocation' || value === 'suspension' || value === 'message';
}

/**
 * 用途と `statusSize` の組を検証して返す。
 *
 * `revocation` / `suspension` は定義上 1 ビット。`message` だけが複数ビットを取れる（Go 実装と同じ）。
 *
 * @throws 用途が列挙外 / `statusSize` が 1..8 の整数でない / 非 `message` で 1 以外の場合（code `3002`）。
 */
function parsePurposeAndSize(
  purpose: unknown,
  statusSize: unknown,
): { purpose: BitstringStatusPurpose; statusSize: number } {
  if (
    !isPurpose(purpose) ||
    typeof statusSize !== 'number' ||
    !Number.isInteger(statusSize) ||
    statusSize < 1 ||
    statusSize > MAX_BITSTRING_STATUS_SIZE ||
    (purpose !== 'message' && statusSize !== 1)
  ) {
    throw invalid();
  }
  return { purpose, statusSize };
}

/** GZIP（RFC 1952）で圧縮する。Web 標準の `CompressionStream` を使う（依存を増やさない）。 */
async function gzip(bytes: Uint8Array): Promise<Uint8Array> {
  const stream = new CompressionStream('gzip') as unknown as {
    writable: WritableStream<Uint8Array>;
    readable: ReadableStream<Uint8Array>;
  };
  return transform(bytes, stream);
}

/** GZIP を展開する。展開後が {@link MAX_DECOMPRESSED_BITSTRING_BYTES} を超える・壊れた入力は 3002。 */
async function gunzip(compressed: Uint8Array): Promise<Uint8Array> {
  const stream = new DecompressionStream('gzip') as unknown as {
    writable: WritableStream<Uint8Array>;
    readable: ReadableStream<Uint8Array>;
  };
  try {
    return await transform(compressed, stream, MAX_DECOMPRESSED_BITSTRING_BYTES);
  } catch {
    throw invalid();
  }
}

/**
 * W3C Bitstring Status List。`length` 個のエントリ（各 `statusSize` ビット）を MSB 先頭で詰める。
 *
 * 並行利用は想定しない（更新は単一の書き込み主体に直列化する。`StatusListManager` と同じ方針）。
 */
export class BitstringStatusList {
  /** 用途。 */
  readonly purpose: BitstringStatusPurpose;
  /** 1 エントリのビット数。 */
  readonly statusSize: number;
  /** エントリ数。 */
  readonly length: number;
  private readonly bytes: Uint8Array;

  private constructor(
    purpose: BitstringStatusPurpose,
    statusSize: number,
    length: number,
    bytes: Uint8Array,
  ) {
    this.purpose = purpose;
    this.statusSize = statusSize;
    this.length = length;
    this.bytes = bytes;
  }

  /**
   * 全ビット 0 のリストを生成する（W3C §3.1 Bitstring Generation）。
   *
   * @param purpose 用途（`revocation` / `suspension` / `message`）。
   * @param statusSize 1 エントリのビット数（1..8。`message` 以外は 1）。
   * @param length エントリ数。`length * statusSize` が最小長（131,072 ビット）以上であること。
   * @returns 空のリスト。
   * @throws 用途・`statusSize` が不正 / 最小長未満 / 展開後上限（8 MiB）超過の場合
   *   （VericertsError、code `3002`）。
   */
  static create(
    purposeInput: BitstringStatusPurpose,
    statusSizeInput: number,
    length: number,
  ): BitstringStatusList {
    const { purpose, statusSize } = parsePurposeAndSize(purposeInput, statusSizeInput);
    if (
      !Number.isInteger(length) ||
      length <= 0 ||
      length * statusSize < MIN_BITSTRING_STATUS_LIST_BITS ||
      length * statusSize > MAX_DECOMPRESSED_BITSTRING_BYTES * 8
    ) {
      throw invalid();
    }
    return new BitstringStatusList(
      purpose,
      statusSize,
      length,
      new Uint8Array(Math.ceil((length * statusSize) / 8)),
    );
  }

  /**
   * `encodedList` を復号する（W3C §3.2 Validate Algorithm の Bitstring Expansion と最小長検査）。
   *
   * @param encodedList multibase base64url（`u` 接頭辞）の GZIP 圧縮ビット列。
   * @param purpose リスト VC の `statusPurpose`。
   * @param statusSize リスト VC の `statusSize`（省略時 1）。
   * @returns 復号したリスト（エントリ数は `floor(ビット長 / statusSize)`）。
   * @throws 接頭辞なし / base64url・GZIP として不正 / 空 / 展開後 8 MiB 超過 / 用途・`statusSize`
   *   不正 / 最小長（131,072 ビット）未満（`STATUS_LIST_LENGTH_ERROR`）の場合（code `3002`）。
   */
  static async decode(
    encodedList: unknown,
    purposeInput: unknown,
    statusSizeInput: unknown = 1,
  ): Promise<BitstringStatusList> {
    const { purpose, statusSize } = parsePurposeAndSize(purposeInput, statusSizeInput);
    if (
      typeof encodedList !== 'string' ||
      !encodedList.startsWith(MULTIBASE_BASE64URL) ||
      encodedList.length > MAX_ENCODED_LIST_LENGTH
    ) {
      throw invalid();
    }
    let compressed: Uint8Array;
    try {
      compressed = base64urlnopad.decode(encodedList.slice(MULTIBASE_BASE64URL.length));
    } catch {
      throw invalid();
    }
    const bytes = await gunzip(compressed);
    // 空リストと最小長（herd privacy）未満は同じ 3002。最小長は生成時の規則だが W3C §3.2 は
    // 検証側にも課す（STATUS_LIST_LENGTH_ERROR）。短いリストは個々のエントリが特定されやすい。
    if (bytes.length === 0 || bytes.length * 8 < MIN_BITSTRING_STATUS_LIST_BITS) {
      throw invalid();
    }
    return new BitstringStatusList(
      purpose,
      statusSize,
      Math.floor((bytes.length * 8) / statusSize),
      bytes,
    );
  }

  /**
   * インデックス `index` のエントリ値を読む（`statusSize` ビットを MSB 先頭の整数として）。
   *
   * @throws `index` が整数でない / 範囲外の場合（code `3002`）。
   */
  get(index: number): number {
    this.assertIndex(index);
    let value = 0;
    for (let b = 0; b < this.statusSize; b++) {
      const pos = index * this.statusSize + b;
      value = (value << 1) | (((this.bytes[pos >> 3] ?? 0) >> (7 - (pos & 7))) & 1);
    }
    return value;
  }

  /**
   * インデックス `index` のエントリ値を書く。
   *
   * @throws `index` が範囲外 / `value` が `[0, 2^statusSize)` の整数でない場合（code `3002`）。
   */
  set(index: number, value: number): void {
    this.assertIndex(index);
    if (!Number.isInteger(value) || value < 0 || value >= 1 << this.statusSize) {
      throw invalid();
    }
    for (let b = 0; b < this.statusSize; b++) {
      const pos = index * this.statusSize + b;
      const mask = 1 << (7 - (pos & 7));
      const current = this.bytes[pos >> 3] ?? 0;
      const bit = (value >> (this.statusSize - 1 - b)) & 1;
      this.bytes[pos >> 3] = bit === 1 ? current | mask : current & ~mask;
    }
  }

  /**
   * `encodedList`（multibase base64url の GZIP 圧縮ビット列）を返す。
   *
   * @returns `u` + base64url(GZIP(bitstring))。
   */
  async encode(): Promise<string> {
    return `${MULTIBASE_BASE64URL}${base64urlnopad.encode(await gzip(this.bytes))}`;
  }

  private assertIndex(index: number): void {
    if (!Number.isInteger(index) || index < 0 || index >= this.length) {
      throw invalid();
    }
  }
}
