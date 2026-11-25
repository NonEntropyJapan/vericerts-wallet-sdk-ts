/**
 * multihash（`<varint hash-code><varint digest-length><digest>`）のデコード。
 *
 * `<alg>-<digest>` 形式ではなく、
 * multibase でくるんだ multihash（例 IPFS 系の CID 断片）で contentHash が渡される
 * ケースを吸収する。
 *
 * `identity/multibase.ts` の `encodeMulticodecVarint` で canonical 再エンコード照合を行い、
 * 非 canonical varint（継続ビットの誤用による同値表現）を拒否する。`method-key.ts` の
 * varint 判定と同じイディオム。
 */

import { encodeMulticodecVarint } from '../multibase.js';

/** varint 1 個の読み取り結果。 */
interface VarintRead {
  readonly value: number;
  readonly nextOffset: number;
}

/** varint 1 個あたりの最大バイト数（32bit 値の unsigned LEB128 は 5 バイト）。 */
const MAX_VARINT_BYTES = 5;

/**
 * unsigned LEB128 varint を 1 個読み取る。
 *
 * 非 canonical なエンコード（同じ値をより長いバイト列で表現したもの）は拒否する。
 *
 * @param bytes 読み取り元。
 * @param offset 読み取り開始位置。
 * @returns 値と次の読み取り位置。不正なら `undefined`。
 */
function readVarint(bytes: Uint8Array, offset: number): VarintRead | undefined {
  let value = 0;
  let shift = 0;
  let index = offset;
  for (let count = 0; count < MAX_VARINT_BYTES; count++) {
    const byte = bytes[index];
    if (byte === undefined) {
      return undefined;
    }
    index += 1;
    value += (byte & 0x7f) * 2 ** shift;
    if ((byte & 0x80) === 0) {
      const canonical = encodeMulticodecVarint(value);
      if (canonical.length !== index - offset) {
        // 継続ビットを無駄に使った非 canonical 表現。
        return undefined;
      }
      return { value, nextOffset: index };
    }
    shift += 7;
  }
  return undefined;
}

/** multihash のデコード結果。 */
export interface DecodedMultihash {
  /** ハッシュ関数の multihash コード。 */
  readonly code: number;
  /** ダイジェスト本体。 */
  readonly digest: Uint8Array;
}

/**
 * multihash バイト列をデコードする。
 *
 * @param bytes `<varint code><varint length><digest>` のバイト列。
 * @returns コードとダイジェスト。形式不正・長さ不一致・余剰バイトがある場合は `undefined`。
 */
export function decodeMultihash(bytes: Uint8Array): DecodedMultihash | undefined {
  const codeRead = readVarint(bytes, 0);
  if (codeRead === undefined) {
    return undefined;
  }
  const lengthRead = readVarint(bytes, codeRead.nextOffset);
  if (lengthRead === undefined) {
    return undefined;
  }
  const digest = bytes.subarray(lengthRead.nextOffset);
  // 宣言長と実バイト数の不一致・末尾余剰バイトはいずれも拒否する（fail-closed）。
  if (digest.length !== lengthRead.value || lengthRead.value === 0) {
    return undefined;
  }
  return { code: codeRead.value, digest };
}
