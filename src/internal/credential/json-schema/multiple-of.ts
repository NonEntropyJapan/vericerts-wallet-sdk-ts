/**
 * JSON Schema `multipleOf` の厳密判定。
 *
 * 浮動小数の商 `value / multipleOf` に**絶対**許容誤差を掛けて整数判定すると、`0.28 / 0.01 =
 * 28.000000000000004` のような 0.01 刻みの正当な値を誤拒否し、`1e20` のように商が巨大な非倍数を
 * 誤受理する。通貨・割合の `multipleOf: 0.01` は VC スキーマで典型のため、両数を 10 進表記
 * （JavaScript が往復保証する最短表現）から `BigInt` の整数へ揃えて剰余で判定する。
 */

/** 10 進表記の数値: 符号 / 整数部 / 小数部 / 指数部。 */
const DECIMAL = /^(-?)(\d+)(?:\.(\d+))?(?:e([+-]\d+))?$/;

/** 有限数を `significand * 10^-scale`（`significand` は符号付き整数）へ分解する。 */
function toScaledInteger(value: number): { significand: bigint; scale: number } {
  const m = DECIMAL.exec(value.toString());
  if (m === null) {
    // 有限数の `toString()` は常に DECIMAL に一致する。到達不能だが、握りつぶさず失敗させる。
    throw new TypeError('有限数の 10 進表記に分解できません');
  }
  const [, sign = '', integerPart = '0', fraction = '', exponent = '0'] = m;
  const significand = BigInt(`${sign}${integerPart}${fraction}`);
  return { significand, scale: fraction.length - Number(exponent) };
}

/**
 * `value` が `multipleOf`（> 0）の整数倍かを 10 進で厳密に判定する。
 *
 * 非有限の `value` / `multipleOf` は倍数と認めない（fail-closed）。
 */
export function isMultipleOf(value: number, multipleOf: number): boolean {
  if (!Number.isFinite(value) || !Number.isFinite(multipleOf) || multipleOf <= 0) {
    return false;
  }
  const a = toScaledInteger(value);
  const b = toScaledInteger(multipleOf);
  // 小数点位置（scale）を大きい側へ揃え、指数が負（= 整数側へ伸ばす）の場合も同じ式で扱う。
  const scale = Math.max(a.scale, b.scale);
  const aInt = a.significand * 10n ** BigInt(scale - a.scale);
  const bInt = b.significand * 10n ** BigInt(scale - b.scale);
  return aInt % bInt === 0n;
}
