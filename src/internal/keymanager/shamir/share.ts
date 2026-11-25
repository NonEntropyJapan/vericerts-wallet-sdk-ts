/**
 * SLIP-0039 シェアのメタデータ ⇔ ニーモニックの相互変換（spec §Format of the share mnemonic）。
 *
 * ビット詰め（id/ext/e/group.../チェックサム）は spec のフィールド定義をそのまま実装する。
 * 多倍長整数の扱いは JS の `number`（53bit 精度）では 256bit マスターシークレットに足りない
 * ため `bigint` を使う。
 */

import { createChecksum, verifyChecksum } from './rs1024.js';
import { mnemonicToIndices, wordsFromIndices } from './wordlist.js';

const RADIX_BITS = 10;
const ID_LENGTH_BITS = 15;
const EXTENDABLE_FLAG_LENGTH_BITS = 1;
const ITERATION_EXP_LENGTH_BITS = 4;
const ID_EXP_LENGTH_WORDS = Math.ceil(
  (ID_LENGTH_BITS + EXTENDABLE_FLAG_LENGTH_BITS + ITERATION_EXP_LENGTH_BITS) / RADIX_BITS,
);
const CHECKSUM_LENGTH_WORDS = 3;
const METADATA_LENGTH_WORDS = ID_EXP_LENGTH_WORDS + 2 + CHECKSUM_LENGTH_WORDS;
const MIN_STRENGTH_BITS = 128;
const MIN_MNEMONIC_LENGTH_WORDS = METADATA_LENGTH_WORDS + Math.ceil(MIN_STRENGTH_BITS / RADIX_BITS);

const CUSTOMIZATION_STRING_ORIG = 'shamir';
const CUSTOMIZATION_STRING_EXTENDABLE = 'shamir_extendable';

function customizationString(extendable: boolean): string {
  return extendable ? CUSTOMIZATION_STRING_EXTENDABLE : CUSTOMIZATION_STRING_ORIG;
}

/** 桁配列（big-endian）⇔ bigint の相互変換（word index は radixBits=10、share params は 4）。 */
function indicesFromInt(value: bigint, length: number, radixBits: number): number[] {
  const mask = (1n << BigInt(radixBits)) - 1n;
  const result: number[] = [];
  for (let i = length - 1; i >= 0; i--) {
    result.push(Number((value >> (BigInt(i) * BigInt(radixBits))) & mask));
  }
  return result;
}

function intFromIndices(indices: readonly number[], radixBits: number): bigint {
  const radix = 1n << BigInt(radixBits);
  let value = 0n;
  for (const index of indices) {
    value = value * radix + BigInt(index);
  }
  return value;
}

function bytesToBigInt(bytes: Uint8Array): bigint {
  let value = 0n;
  for (const byte of bytes) {
    value = (value << 8n) | BigInt(byte);
  }
  return value;
}

/** @throws `value` が `byteLength` バイトに収まらない場合（パディング不正、`Error`）。 */
function bigIntToBytes(value: bigint, byteLength: number): Uint8Array {
  const bytes = new Uint8Array(byteLength);
  let remaining = value;
  for (let i = byteLength - 1; i >= 0; i--) {
    bytes[i] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
  if (remaining !== 0n) {
    throw new Error('SLIP-0039: value does not fit in expected byte length');
  }
  return bytes;
}

/** 1 枚の SLIP-0039 シェア（デコード済みメタデータ + シェア値）。 */
export interface Share {
  readonly identifier: number;
  readonly extendable: boolean;
  readonly iterationExponent: number;
  readonly groupIndex: number;
  readonly groupThreshold: number;
  readonly groupCount: number;
  readonly index: number;
  readonly memberThreshold: number;
  readonly value: Uint8Array;
}

function encodeIdExp(
  share: Pick<Share, 'identifier' | 'extendable' | 'iterationExponent'>,
): number[] {
  let idExp =
    BigInt(share.identifier) << BigInt(ITERATION_EXP_LENGTH_BITS + EXTENDABLE_FLAG_LENGTH_BITS);
  idExp += BigInt(share.extendable ? 1 : 0) << BigInt(ITERATION_EXP_LENGTH_BITS);
  idExp += BigInt(share.iterationExponent);
  return indicesFromInt(idExp, ID_EXP_LENGTH_WORDS, RADIX_BITS);
}

function encodeShareParams(
  share: Pick<Share, 'groupIndex' | 'groupThreshold' | 'groupCount' | 'index' | 'memberThreshold'>,
): number[] {
  let value = BigInt(share.groupIndex);
  value = (value << 4n) + BigInt(share.groupThreshold - 1);
  value = (value << 4n) + BigInt(share.groupCount - 1);
  value = (value << 4n) + BigInt(share.index);
  value = (value << 4n) + BigInt(share.memberThreshold - 1);
  // 20bit の値を 2 ワード（各 10bit、RADIX_BITS）としてエンコードする。
  return indicesFromInt(value, 2, RADIX_BITS);
}

/** シェアをニーモニック（空白区切りの単語列）へ変換する。 */
export function shareToMnemonic(share: Share): string {
  const valueWordCount = Math.ceil((share.value.length * 8) / RADIX_BITS);
  const valueData = indicesFromInt(bytesToBigInt(share.value), valueWordCount, RADIX_BITS);
  const shareData = [...encodeIdExp(share), ...encodeShareParams(share), ...valueData];
  const checksum = createChecksum(shareData, customizationString(share.extendable));
  return wordsFromIndices([...shareData, ...checksum]).join(' ');
}

/**
 * 受理するシェア値の最大バイト長。この SDK が生成する値は言語タグ 2 + エントロピー 16/32 = 最大 34 バイト、
 * SLIP-0039 の標準ベクトルも最大 32 バイト。値長に比例する PBKDF2 / GF(256) 補間 / 多倍長整数変換を、改変された
 * 巨大シェアで長時間占有されないよう復号の入口で打ち切る。
 */
export const MAX_SHARE_VALUE_BYTES = 34;

/**
 * 復旧入力のニーモニックをシェアへ復号し、PBKDF2 / 補間へ渡してよいものだけを通す。
 *
 * 次のいずれかなら `undefined`（呼び出し側は `invalid_share`）: 枚数が `maxShares` 超、ニーモニックが不正、
 * 反復回数指数が `maxIterationExponent` 超、値長が `createShares` の生成する 18 / 34 バイト（言語タグ 2 +
 * BIP-39 エントロピー 16 / 32）以外。コストはいずれにも比例するため、改変シェア 1 枚で同期 PBKDF2 を占有させない。
 */
export function decodeRecoverableShares(
  mnemonics: readonly string[],
  maxShares: number,
  maxIterationExponent: number,
): Share[] | undefined {
  if (mnemonics.length > maxShares) {
    return undefined;
  }
  try {
    const shares = mnemonics.map(shareFromMnemonic);
    const accepted = shares.every(
      (share) =>
        share.iterationExponent <= maxIterationExponent &&
        (share.value.length === 18 || share.value.length === MAX_SHARE_VALUE_BYTES),
    );
    return accepted ? shares : undefined;
  } catch {
    return undefined;
  }
}
const MAX_MNEMONIC_LENGTH_WORDS =
  METADATA_LENGTH_WORDS + Math.ceil((MAX_SHARE_VALUE_BYTES * 8) / RADIX_BITS);
/** 1 シェアの最大文字数。最長 8 文字の単語 × 最大語数 + 区切り空白に、整形用の余白を加えた値。 */
const MAX_MNEMONIC_CHARS = 1024;

/**
 * ニーモニックをシェアへ変換する。
 *
 * @throws 未知の単語、長さ不正（過大を含む）、チェックサム不正、パディング不正の場合（`Error`。
 *         呼び出し側で `recoverFromShamirShares` の status へ正規化する）。
 */
export function shareFromMnemonic(mnemonic: string): Share {
  if (mnemonic.length > MAX_MNEMONIC_CHARS) {
    throw new Error('SLIP-0039: mnemonic is too long');
  }
  const mnemonicData = mnemonicToIndices(mnemonic);

  if (mnemonicData.length < MIN_MNEMONIC_LENGTH_WORDS) {
    throw new Error('SLIP-0039: mnemonic is too short');
  }
  if (mnemonicData.length > MAX_MNEMONIC_LENGTH_WORDS) {
    throw new Error('SLIP-0039: mnemonic is too long');
  }

  const paddingLen = (RADIX_BITS * (mnemonicData.length - METADATA_LENGTH_WORDS)) % 16;
  if (paddingLen > 8) {
    throw new Error('SLIP-0039: invalid mnemonic length');
  }

  const idExpInt = intFromIndices(mnemonicData.slice(0, ID_EXP_LENGTH_WORDS), RADIX_BITS);
  const identifier = Number(
    idExpInt >> BigInt(EXTENDABLE_FLAG_LENGTH_BITS + ITERATION_EXP_LENGTH_BITS),
  );
  const extendable = ((idExpInt >> BigInt(ITERATION_EXP_LENGTH_BITS)) & 1n) === 1n;
  const iterationExponent = Number(idExpInt & ((1n << BigInt(ITERATION_EXP_LENGTH_BITS)) - 1n));

  if (!verifyChecksum(mnemonicData, customizationString(extendable))) {
    throw new Error('SLIP-0039: invalid mnemonic checksum');
  }

  const shareParamsData = mnemonicData.slice(ID_EXP_LENGTH_WORDS, ID_EXP_LENGTH_WORDS + 2);
  const shareParamsInt = intFromIndices(shareParamsData, RADIX_BITS);
  const shareParams = indicesFromInt(shareParamsInt, 5, 4);
  if (shareParams.length !== 5) {
    // indicesFromInt(value, 5, ...) は常に 5 要素を返す（内部不変条件）。
    throw new Error('SLIP-0039: internal error decoding share params');
  }
  const [groupIndex, groupThresholdEnc, groupCountEnc, index, memberThresholdEnc] = shareParams as [
    number,
    number,
    number,
    number,
    number,
  ];

  if (groupCountEnc < groupThresholdEnc) {
    throw new Error('SLIP-0039: group threshold cannot be greater than group count');
  }

  const valueData = mnemonicData.slice(
    ID_EXP_LENGTH_WORDS + 2,
    mnemonicData.length - CHECKSUM_LENGTH_WORDS,
  );
  const valueByteCount = Math.ceil((RADIX_BITS * valueData.length - paddingLen) / 8);
  const value = bigIntToBytes(intFromIndices(valueData, RADIX_BITS), valueByteCount);

  return {
    identifier,
    extendable,
    iterationExponent,
    groupIndex,
    groupThreshold: groupThresholdEnc + 1,
    groupCount: groupCountEnc + 1,
    index,
    memberThreshold: memberThresholdEnc + 1,
    value,
  };
}
