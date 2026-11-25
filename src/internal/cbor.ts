/**
 * CBOR（RFC 8949）のデータ項目を「中身を解釈せずに歩く」ための最小限の読み書き。
 *
 * 値の復元は不要で、必要なのは「どこからどこまでが何番目の要素か」だけなので、汎用の CBOR
 * デコーダは持ち込まず head の解析に絞る（依存を増やさず、想定外の入力で重い処理をしない）。
 *
 * additional information 28〜31（予約・不定長）は扱わない。COSE の preferred serialization は
 * 常に定長であり、対応しないことによる取りこぼしは呼び出し側の安全側（マスクしない / COSE と
 * 見なさない）へ倒すだけで済む。
 *
 * ログの COSE payload マスキングと、VP に含まれる VC の形式判別で同じ読み取り処理を使う。
 */

/** CBOR head の additional information と、後続する引数バイト数の対応（RFC 8949 §3）。 */
const CBOR_ARGUMENT_FORMS = [
  { max: 0xff, info: 24, width: 1 },
  { max: 0xffff, info: 25, width: 2 },
  { max: 0xffffffff, info: 26, width: 4 },
  { max: Number.MAX_SAFE_INTEGER, info: 27, width: 8 },
] as const;

/** 引数を head に直接埋め込める上限（RFC 8949 §3）。 */
const CBOR_INLINE_ARGUMENT_MAX = 23;

/** CBOR の major type（RFC 8949 §3.1）。 */
export const CBOR_MAJOR = {
  unsigned: 0,
  negative: 1,
  byteString: 2,
  textString: 3,
  array: 4,
  map: 5,
  tag: 6,
  simple: 7,
} as const;

/** CBOR データ項目の head（RFC 8949 §3）。 */
export interface CborHeader {
  /** major type（先頭バイトの上位 3bit）。 */
  readonly majorType: number;
  /** head が表す引数値（長さ / 整数値 / simple 値）。 */
  readonly value: number;
  /** head 自体のバイト数。 */
  readonly headerLen: number;
}

/**
 * `offset` 位置の CBOR head を読む。
 *
 * @param bytes 解析対象のバイト列。
 * @param offset 読み始める位置。
 * @returns 読み取った head。範囲外・未対応の additional information なら `undefined`。
 */
export function readCborHeader(bytes: Uint8Array, offset: number): CborHeader | undefined {
  const first = bytes[offset];
  if (first === undefined) {
    return undefined;
  }
  const majorType = first >> 5;
  const info = first & 0x1f;
  if (info <= CBOR_INLINE_ARGUMENT_MAX) {
    return { majorType, value: info, headerLen: 1 };
  }
  const form = CBOR_ARGUMENT_FORMS.find((candidate) => candidate.info === info);
  if (form === undefined) {
    return undefined;
  }
  const headerLen = 1 + form.width;
  if (offset + headerLen > bytes.length) {
    return undefined;
  }
  let argument = 0n;
  for (let i = 1; i <= form.width; i += 1) {
    argument = (argument << 8n) | BigInt(bytes[offset + i] ?? 0);
  }
  // 安全整数を超える引数はオフセット計算が壊れるため、解析を諦める（fail-closed）。
  return argument > BigInt(Number.MAX_SAFE_INTEGER)
    ? undefined
    : { majorType, value: Number(argument), headerLen };
}

/**
 * 定長データ項目の CBOR head を組み立てる（`readCborHeader` の逆）。
 *
 * @param majorType 組み立てる項目の major type。
 * @param length 引数値（byte string / text string なら長さ）。
 * @returns head のバイト列。
 * @throws RangeError `length` が安全整数を超える場合。
 */
export function encodeCborHeader(majorType: number, length: number): Uint8Array {
  const prefix = majorType << 5;
  if (length <= CBOR_INLINE_ARGUMENT_MAX) {
    return Uint8Array.of(prefix | length);
  }
  const form = CBOR_ARGUMENT_FORMS.find((candidate) => length <= candidate.max);
  if (form === undefined) {
    throw new RangeError('cbor argument out of range');
  }
  const head = new Uint8Array(1 + form.width);
  head[0] = prefix | form.info;
  let rest = BigInt(length);
  for (let i = form.width; i >= 1; i -= 1) {
    head[i] = Number(rest & 0xffn);
    rest >>= 8n;
  }
  return head;
}
