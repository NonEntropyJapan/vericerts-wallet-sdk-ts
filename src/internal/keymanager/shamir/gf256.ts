/**
 * GF(256) 上の Lagrange 補間（SLIP-0039 Shamir 秘密分散の多項式演算、spec §Polynomial interpolation）。
 *
 * バイト列を GF(256) の要素とみなし、AES と同じ既約多項式 x^8 + x^4 + x^3 + x + 1（0x11B）で
 * 演算する。EXP/LOG 表による乗除算は spec 記載の Python 参照実装と同一のアルゴリズム。
 */

interface ExpLogTables {
  readonly exp: readonly number[];
  readonly log: readonly number[];
}

function precomputeExpLog(): ExpLogTables {
  const exp = new Array<number>(255).fill(0);
  const log = new Array<number>(256).fill(0);
  let poly = 1;
  for (let i = 0; i < 255; i++) {
    exp[i] = poly;
    log[poly] = i;
    // poly を多項式 x + 1 倍する。
    poly = (poly << 1) ^ poly;
    // x^8 + x^4 + x^3 + x + 1 で還元する。
    if (poly & 0x100) {
      poly ^= 0x11b;
    }
  }
  return { exp, log };
}

const { exp: EXP_TABLE, log: LOG_TABLE } = precomputeExpLog();

function mod255(n: number): number {
  return ((n % 255) + 255) % 255;
}

/**
 * EXP/LOG 表を範囲チェック付きで参照する。呼び出し側の入力（x 座標・バイト値は常に
 * 0-255、mod255 後の値は常に 0-254）から、実際に範囲外になることはない防御的な安全弁。
 */
function tableGet(table: readonly number[], index: number): number {
  const value = table[index];
  if (value === undefined) {
    throw new Error('SLIP-0039: table index out of range');
  }
  return value;
}

/** Shamir シェアの 1 点（x 座標と、その点でのバイト列評価値）。 */
export interface RawShare {
  readonly x: number;
  readonly data: Uint8Array;
}

/**
 * 与えられた Shamir シェア群から、多項式を x で評価した値（バイト列）を復元する。
 *
 * `x` が既存シェアの x 座標と一致する場合はその値をそのまま返す（補間不要）。
 *
 * @throws x 座標に重複がある場合、シェア値の長さが揃っていない場合（`Error`。
 *         呼び出し側で status / VericertsError へ正規化する）。
 */
export function interpolate(shares: readonly RawShare[], x: number): Uint8Array {
  const xCoordinates = new Set(shares.map((share) => share.x));
  if (xCoordinates.size !== shares.length) {
    throw new Error('SLIP-0039: duplicate share x-coordinates');
  }
  const lengths = new Set(shares.map((share) => share.data.length));
  if (lengths.size !== 1) {
    throw new Error('SLIP-0039: share value lengths do not match');
  }

  const existing = shares.find((share) => share.x === x);
  if (existing !== undefined) {
    return existing.data;
  }

  let logProd = 0;
  for (const share of shares) {
    logProd += tableGet(LOG_TABLE, share.x ^ x);
  }

  const length = lengths.values().next().value as number;
  const result = new Uint8Array(length);
  for (const share of shares) {
    let logSumOther = 0;
    for (const other of shares) {
      if (other !== share) {
        logSumOther += tableGet(LOG_TABLE, share.x ^ other.x);
      }
    }
    const logBasisEval = mod255(logProd - tableGet(LOG_TABLE, share.x ^ x) - logSumOther);
    for (let k = 0; k < length; k++) {
      const shareByte = share.data[k];
      if (shareByte !== undefined && shareByte !== 0) {
        result[k] =
          (result[k] ?? 0) ^
          tableGet(EXP_TABLE, mod255(tableGet(LOG_TABLE, shareByte) + logBasisEval));
      }
    }
  }
  return result;
}
