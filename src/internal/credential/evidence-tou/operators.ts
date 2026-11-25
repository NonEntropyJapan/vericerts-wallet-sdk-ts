/**
 * ODRL 制約の比較演算子の実装（`odrl.ts` の下位ロジック）。
 *
 * サポート語彙は `types.ts` の `OdrlOperator` を SoT とする。対応外の演算子は `undefined` を返し、
 * 「制約不成立」ではなく「評価不能」であることを呼び出し側へ伝える（fail-closed 評価で使う）。
 *
 * セキュリティ: 例外 message / context に VC 本文（ToU の値）を含めない。
 */

import { isoToNumericDate } from '../vc/numeric-date.js';

/**
 * 文字列制約（purpose / spatial）を比較する。left 未指定は「合致しない」= false。
 *
 * 対応演算子（`OdrlOperator`）: `eq` / `neq` / `isAnyOf` / `isPartOf` / `isNoneOf`。
 * それ以外（`lt` 等の時刻専用演算子・未知の演算子）は評価不能として `undefined` を返す。
 * 対応演算子でも `left` が未指定なら「合致しない」= false（評価はできている）。
 */
export function compareString(
  left: string | undefined,
  operator: string,
  right: string | readonly string[],
): boolean | undefined {
  const rights = Array.isArray(right) ? right : [right as string];
  switch (operator) {
    case 'eq':
      return left !== undefined && rights.length === 1 && left === rights[0];
    case 'neq':
      return left !== undefined && rights.length === 1 && left !== rights[0];
    case 'isAnyOf':
    case 'isPartOf':
      return left !== undefined && rights.includes(left);
    case 'isNoneOf':
      return left !== undefined && !rights.includes(left);
    default:
      return undefined;
  }
}

/**
 * 時刻制約（dateTime）がサポートする演算子。
 *
 * `isoToNumericDate` は不正 ISO で throw するため、日時のパースに進む前に演算子の対応可否を
 * 判定する（対応外演算子は「評価不能」であって構造エラーではない）。
 */
const DATE_TIME_OPERATORS: ReadonlySet<string> = new Set(['lt', 'lteq', 'gt', 'gteq', 'eq', 'neq']);

/**
 * 時刻制約（dateTime）を ISO 比較で評価する。
 *
 * 対応演算子（`OdrlOperator`）: `lt` / `lteq` / `gt` / `gteq` / `eq` / `neq`。
 * それ以外（`isAnyOf` 等の文字列専用演算子・未知の演算子）は評価不能として `undefined` を返す。
 * `rightOperand` が文字列でない場合は「合致しない」= false（評価はできている）。
 *
 * `rightOperand`（VC 本文由来）が不正な ISO の場合は**例外にせず評価不能（`undefined`）として返す**。
 * 呼び出し側はこの結果を fail-closed では `deny` 違反、fail-open では制約不成立として扱う。
 *
 * 一方 `nowIso`（`UsageContext.at`。**呼び出し側入力**）の不正は握り潰さず `VC_SCHEMA_INVALID`
 * （3002）を送出する。これを評価不能に倒すと、呼び出し側のバグで全 `dateTime` 制約が黙って
 * 不成立になり、発火すべき `prohibition` が消えるためである。
 *
 * @throws `nowIso` が不正な ISO の場合（`VC_SCHEMA_INVALID` 3002）。
 */
export function compareDateTime(
  nowIso: string,
  operator: string,
  right: string | readonly string[],
): boolean | undefined {
  if (!DATE_TIME_OPERATORS.has(operator)) {
    return undefined;
  }
  const rightIso = Array.isArray(right) ? right[0] : (right as string);
  if (typeof rightIso !== 'string') {
    return false;
  }
  // 呼び出し側入力。不正なら従来どおり 3002 を送出する（黙って不成立に倒さない）。
  const now = isoToNumericDate(nowIso);
  let bound: number;
  try {
    // VC 本文由来。構造不正な制約は例外ではなく評価不能として返す（上記 JSDoc 参照）。
    bound = isoToNumericDate(rightIso);
  } catch {
    return undefined;
  }
  switch (operator) {
    case 'lt':
      return now < bound;
    case 'lteq':
      return now <= bound;
    case 'gt':
      return now > bound;
    case 'gteq':
      return now >= bound;
    case 'eq':
      return now === bound;
    default:
      // DATE_TIME_OPERATORS で絞り込み済みのため 'neq' のみが残る。
      return now !== bound;
  }
}
