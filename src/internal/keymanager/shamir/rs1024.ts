/**
 * SLIP-0039 の RS1024 チェックサム（GF(1024) 上の Reed-Solomon 符号、spec §Checksum）。
 *
 * BIP-173 (Bech32) のチェックサムと同系の設計。3 ワード（30 bit）のチェックサムで
 * 3 ワード以下の誤りを確実に検出する。本モジュールは spec 記載の Python 参照実装を
 * そのまま TypeScript に移植したもので、独自の最適化は行わない。
 */

const CHECKSUM_LENGTH_WORDS = 3;

/** RS1024 の生成多項式（GF(1024) 上、spec §Checksum に記載の 10 個の定数）。 */
const GENERATOR = [
  0xe0e040, 0x1c1c080, 0x3838100, 0x7070200, 0xe0e0009, 0x1c0c2412, 0x38086c24, 0x3090fc48,
  0x21b1f890, 0x3f3f120,
] as const;

function polymod(values: readonly number[]): number {
  let chk = 1;
  for (const v of values) {
    const b = chk >> 20;
    chk = ((chk & 0xfffff) << 10) ^ v;
    for (let i = 0; i < 10; i++) {
      if ((b >> i) & 1) {
        // GENERATOR は 10 要素固定（ループ範囲 0-9）のため実際には undefined にならない。
        chk ^= GENERATOR[i] ?? 0;
      }
    }
  }
  return chk;
}

/** カスタマイズ文字列（US-ASCII）を文字コードの配列に変換する。 */
function customizationValues(customizationString: string): number[] {
  return Array.from(customizationString, (ch) => ch.charCodeAt(0));
}

/**
 * データ部（10bit 整数の配列）に対する RS1024 チェックサムを生成する。
 *
 * @param data 10bit 整数（ワードインデックス）の配列。
 * @param customizationString `shamir`（ext=0）または `shamir_extendable`（ext=1）。
 * @returns チェックサム（3 ワード分の 10bit 整数）。
 */
export function createChecksum(data: readonly number[], customizationString: string): number[] {
  const values = [...customizationValues(customizationString), ...data, 0, 0, 0];
  const mod = polymod(values) ^ 1;
  const checksum: number[] = [];
  for (let i = CHECKSUM_LENGTH_WORDS - 1; i >= 0; i--) {
    checksum.push((mod >> (10 * i)) & 1023);
  }
  return checksum;
}

/**
 * データ部（チェックサムを含む）が有効な RS1024 チェックサムを持つかを検証する。
 *
 * @param data チェックサムを含む 10bit 整数の配列。
 * @param customizationString `shamir`（ext=0）または `shamir_extendable`（ext=1）。
 */
export function verifyChecksum(data: readonly number[], customizationString: string): boolean {
  return polymod([...customizationValues(customizationString), ...data]) === 1;
}
