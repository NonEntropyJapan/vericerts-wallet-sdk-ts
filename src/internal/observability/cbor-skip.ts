/**
 * CBOR データ項目の読み飛ばし（ログの COSE マスキング専用）。
 *
 * `cbor.ts` の head 解析（`readCborHeader`）の上に、入れ子の配列・map・tag を中身を解釈せずに
 * 読み飛ばす処理を載せる。利用者は `pii-mask.ts` だけなので同じ階層に置く。
 */

import { CBOR_MAJOR, readCborHeader } from '../cbor.js';

/**
 * `skipCborItem` が許す入れ子（配列・map・tag）の最大深さ。
 *
 * COSE の header は浅い（RFC 9052）ので、32 段あれば実用上十分。入力長だけでは再帰の深さが
 * 呼び出しスタックの上限に収まる保証がないため、明示的に頭打ちにする。
 */
export const CBOR_MAX_NESTING_DEPTH = 32;

/** CBOR head の additional information（下位 5 bit）のマスク。 */
const CBOR_INFO_MASK = 0x1f;

/** additional information が 31 のとき、byte / text string・配列・map は不定長（RFC 8949 §3.2.1）。 */
const CBOR_INDEFINITE_INFO = 31;

/** 不定長項目の終端を表す break stop code（`0xff`）。 */
export const CBOR_BREAK = 0xff;

/**
 * 不定長の byte / text string・配列・map を終端の break まで読み飛ばす。
 *
 * 不定長を `readCborHeader` の `undefined`（解析不能）として扱うと、tag 付き・不定長で流通する COSE の
 * payload を見つけられずログへそのまま残してしまう。string は同じ major type の**定長**チャンクの
 * 連なり、配列は項目の連なり、map はキーと値の対の連なり。break が現れずに入力が尽きた場合や、
 * 不定長が許されない major type（整数・tag・simple）は `undefined`（壊れた入力）。
 *
 * @throws RangeError 入れ子が `CBOR_MAX_NESTING_DEPTH` を超える場合。
 */
function skipIndefiniteItem(
  bytes: Uint8Array,
  offset: number,
  majorType: number,
  depth: number,
): number | undefined {
  const isString = majorType === CBOR_MAJOR.byteString || majorType === CBOR_MAJOR.textString;
  const isContainer = majorType === CBOR_MAJOR.array || majorType === CBOR_MAJOR.map;
  if (!isString && !isContainer) {
    return undefined;
  }
  if (isContainer && depth >= CBOR_MAX_NESTING_DEPTH) {
    throw new RangeError('cbor nesting too deep');
  }
  let pos = offset + 1;
  for (;;) {
    const next = bytes[pos];
    if (next === undefined) {
      return undefined;
    }
    if (next === CBOR_BREAK) {
      return pos + 1;
    }
    if (isString && (next >> 5 !== majorType || (next & CBOR_INFO_MASK) === CBOR_INDEFINITE_INFO)) {
      // string のチャンクは同じ major type の定長 string でなければならない（入れ子の不定長は不可）。
      return undefined;
    }
    const end = isString
      ? skipCborItem(bytes, pos, depth)
      : skipCborItems(bytes, pos, majorType === CBOR_MAJOR.map ? 2 : 1, 1, depth + 1);
    if (end === undefined) {
      return undefined;
    }
    pos = end;
  }
}

/**
 * `offset` 位置のデータ項目を中身を解釈せずに読み飛ばす。
 *
 * どの分岐も `undefined` を返すか位置を必ず 1 バイト以上進めるため、壊れた入力でも停止する。
 * 再帰の深さは `CBOR_MAX_NESTING_DEPTH` で頭打ちにし、超える入れ子は `RangeError` にする
 * （「壊れた入力」の `undefined` とは区別し、呼び出し側が fail-closed に倒せるようにする）。
 *
 * @param bytes 解析対象のバイト列。
 * @param offset 読み飛ばす項目の開始位置。
 * @param depth 現在の入れ子の深さ（呼び出し側は指定しない）。
 * @returns 次の項目の開始位置。解析できなければ `undefined`。
 * @throws RangeError 入れ子が `CBOR_MAX_NESTING_DEPTH` を超える場合。
 */
export function skipCborItem(bytes: Uint8Array, offset: number, depth = 0): number | undefined {
  const first = bytes[offset];
  if (first !== undefined && (first & CBOR_INFO_MASK) === CBOR_INDEFINITE_INFO) {
    return skipIndefiniteItem(bytes, offset, first >> 5, depth);
  }
  const header = readCborHeader(bytes, offset);
  if (header === undefined) {
    return undefined;
  }
  const pos = offset + header.headerLen;
  const nests =
    header.majorType === CBOR_MAJOR.array ||
    header.majorType === CBOR_MAJOR.map ||
    header.majorType === CBOR_MAJOR.tag;
  if (nests && depth >= CBOR_MAX_NESTING_DEPTH) {
    throw new RangeError('cbor nesting too deep');
  }
  switch (header.majorType) {
    case CBOR_MAJOR.unsigned:
    case CBOR_MAJOR.negative:
    case CBOR_MAJOR.simple:
      // 値は head に収まっており、後続バイトはない。
      return pos;
    case CBOR_MAJOR.byteString:
    case CBOR_MAJOR.textString:
      return pos + header.value <= bytes.length ? pos + header.value : undefined;
    case CBOR_MAJOR.array:
    case CBOR_MAJOR.map:
      // 配列は要素数、map はキーと値の対なのでその 2 倍の項目が続く。
      return skipCborItems(
        bytes,
        pos,
        header.majorType === CBOR_MAJOR.map ? 2 : 1,
        header.value,
        depth + 1,
      );
    case CBOR_MAJOR.tag:
      // タグ番号は head で消費済み。直後の 1 項目だけが続く。
      return skipCborItem(bytes, pos, depth + 1);
    default:
      return undefined;
  }
}

/**
 * 連続する複数のデータ項目を読み飛ばす。
 *
 * @param bytes 解析対象のバイト列。
 * @param offset 読み飛ばし開始位置。
 * @param itemsPerEntry 1 エントリあたりの項目数（map のキーと値なら 2）。
 * @param count エントリ数。
 * @param depth 現在の入れ子の深さ（呼び出し側は指定しない）。
 * @returns 最後の項目の直後の位置。解析できなければ `undefined`。
 * @throws RangeError 入れ子が `CBOR_MAX_NESTING_DEPTH` を超える場合。
 */
export function skipCborItems(
  bytes: Uint8Array,
  offset: number,
  itemsPerEntry: number,
  count: number,
  depth = 0,
): number | undefined {
  let pos = offset;
  for (let i = 0; i < count * itemsPerEntry; i += 1) {
    const next = skipCborItem(bytes, pos, depth);
    if (next === undefined) {
      return undefined;
    }
    pos = next;
  }
  return pos;
}
