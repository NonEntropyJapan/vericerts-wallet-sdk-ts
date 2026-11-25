/**
 * RLP（Recursive Length Prefix）エンコーダ（Ethereum Yellow Paper Appendix B）。
 *
 * `legacy-tx-serializer.ts` が legacy（EIP-155）トランザクションの署名対象バイト列・署名済み
 * 生トランザクションを組み立てるために使う、ethers 非依存の最小実装。バイト文字列（`Uint8Array`）と
 * リスト（`RlpInput[]`）のみを対応範囲とする（本リポジトリが必要とする用途はトランザクションの
 * フィールド列のみで、ネストしたリスト以上の汎用性は不要）。
 *
 * セキュリティ上の注意:
 * - 入力（nonce・アドレス・金額等）を例外メッセージに含めない。
 */

import { concatBytes } from './bytes.js';

export type RlpInput = Uint8Array | readonly RlpInput[];

/** 整数値の長さプレフィックスを組み立てる（Yellow Paper Appendix B の `R_b` / `R_l`）。 */
function encodeLength(length: number, offset: number): Uint8Array {
  if (length < 56) {
    return Uint8Array.of(offset + length);
  }
  const lengthBytes = bigIntToMinimalBytes(BigInt(length));
  return Uint8Array.of(offset + 55 + lengthBytes.length, ...lengthBytes);
}

/** RLP 整数フィールド（nonce / gas / value 等）の上限。EVM の word 幅 uint256 と同じ 2^256 − 1。 */
export const MAX_RLP_INTEGER = (1n << 256n) - 1n;

/**
 * `bigint` を先頭ゼロを持たない最小長の big-endian バイト列へ変換する（`0n` は空配列）。
 * `value` が 2^256 以上なら拒否する（桁数無制限の gas / value で署名処理が停止するのを防ぐ）。
 */
export function bigIntToMinimalBytes(value: bigint): Uint8Array {
  if (value < 0n) {
    throw new Error('RLP エンコード: 負の整数には対応していません');
  }
  if (value > MAX_RLP_INTEGER) {
    throw new Error('RLP エンコード: 整数が uint256 の範囲を超えています');
  }
  if (value === 0n) {
    return new Uint8Array(0);
  }
  const hex = value.toString(16);
  const padded = hex.length % 2 === 0 ? hex : `0${hex}`;
  const bytes = new Uint8Array(padded.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = Number.parseInt(padded.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

/** バイト列先頭のゼロバイトを取り除く（RLP の整数は最小表現のみを許すため、r/s 等に適用する）。 */
export function stripLeadingZeros(bytes: Uint8Array): Uint8Array {
  let start = 0;
  while (start < bytes.length && bytes[start] === 0) start++;
  return bytes.subarray(start);
}

/** RLP エンコードする（バイト文字列は `Uint8Array`、リストはネストした配列で表す）。 */
export function rlpEncode(input: RlpInput): Uint8Array {
  if (input instanceof Uint8Array) {
    if (input.length === 1 && (input[0] as number) < 0x80) {
      return input;
    }
    return concatBytes(encodeLength(input.length, 0x80), input);
  }
  const payload = concatBytes(...input.map(rlpEncode));
  return concatBytes(encodeLength(payload.length, 0xc0), payload);
}
