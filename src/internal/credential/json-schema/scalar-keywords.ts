/**
 * JSON Schema の非再帰キーワード検証（`type` / `enum` / `const` / 文字列 / 数値）。
 *
 * オブジェクト・配列・論理結合は再帰を伴うため
 * `validate.ts` に置く。本ファイルは公開バレルから re-export しない内部実装。
 */

import {
  addError,
  type Context,
  compilePattern,
  consumeScan,
  FORMAT_CHECKS,
  matchesType,
  patternFailureMessage,
  stringScanUnits,
} from './internals.js';
import { deepEqual, hasDuplicateItems } from './json-equal.js';
import { isMultipleOf } from './multiple-of.js';
import type { JsonSchema } from './types.js';

/** 違反メッセージへ載せる型名の最大文字数・件数（スキーマ由来の文字列を全量保持しない）。 */
const MAX_TYPE_NAME_CHARS = 64;
const MAX_TYPE_NAMES_IN_MESSAGE = 8;

function clipTypeName(name: string): string {
  return name.length > MAX_TYPE_NAME_CHARS ? `${name.slice(0, MAX_TYPE_NAME_CHARS)}…` : name;
}

/**
 * `type` が配列（型のユニオン）の場合を検証する。
 *
 * `type` は Issuer 配布のリモートスキーマ由来で、`Array.isArray` を満たしても**要素が文字列とは
 * 限らない**（`{"type": ["number", {}]}` のようなスキーマ自体が不正なケース）。要素をそのまま
 * `join` すると、パース境界で `null` プロトタイプ化された要素の暗黙の `ToPrimitive` が
 * `TypeError: No default value` になり、`validateAgainstSchema` の「例外を投げず違反を `errors` に
 * まとめて返す」契約（`validate.ts` / `internals.ts`）が破れて fail-safe 分岐ごと素通りする
 * そのため message には**文字列要素だけ**を載せ、非文字列要素の混入はスキーマ不正
 * として文言で示す。判定ロジック自体は従来どおり「文字列要素のいずれかに一致するか」で変えない。
 */
function validateTypeUnion(
  ctx: Context,
  type: readonly unknown[],
  value: unknown,
  path: string,
  required: boolean,
): void {
  // スキーマ側配列の要素数を走査量予算へ前払いする（`type` の巨大配列 × 評価ノード数の増幅を止める）。
  if (!consumeScan(ctx.budget, type.length)) {
    addError(ctx, path, 'type 配列が大きすぎるため評価を打ち切りました', required);
    return;
  }
  let stringCount = 0;
  const shown: string[] = [];
  for (const name of type) {
    if (typeof name !== 'string') {
      continue;
    }
    if (matchesType(value, name)) {
      return;
    }
    stringCount += 1;
    if (shown.length < MAX_TYPE_NAMES_IN_MESSAGE) {
      shown.push(clipTypeName(name));
    }
  }
  if (stringCount === 0) {
    addError(ctx, path, 'type 配列に型名の文字列が無く、スキーマとして不正です', required);
    return;
  }
  const malformed =
    stringCount === type.length ? '' : '（type 配列に文字列でない要素が含まれます）';
  const omitted = stringCount > shown.length ? ` | …他 ${stringCount - shown.length} 件` : '';
  addError(
    ctx,
    path,
    `型が ${shown.join(' | ')}${omitted} のいずれでもありません${malformed}`,
    required,
  );
}

/**
 * `enum` の候補と等価な要素があるか。走査量の予算を使い切ったら残りの候補を比較せず打ち切る
 * （`deepEqual` は尽きた後 `false` を返すだけなので、そのままだと E × N のループが全要素回る）。
 */
function matchesEnum(ctx: Context, candidates: readonly unknown[], value: unknown): boolean {
  for (const candidate of candidates) {
    if (deepEqual(candidate, value, ctx.budget)) {
      return true;
    }
    if (ctx.budget.exhausted) {
      return false;
    }
  }
  return false;
}

/** `type` / `enum` / `const` を検証する。 */
export function validateCore(
  ctx: Context,
  schema: JsonSchema,
  value: unknown,
  path: string,
  required: boolean,
): void {
  const type = schema.type;
  if (typeof type === 'string' && !matchesType(value, type)) {
    addError(ctx, path, `型が ${clipTypeName(type)} ではありません`, required);
  } else if (Array.isArray(type)) {
    validateTypeUnion(ctx, type, value, path, required);
  }
  if (Array.isArray(schema.enum) && !matchesEnum(ctx, schema.enum, value)) {
    addError(ctx, path, 'enum に列挙された値ではありません', required);
  }
  if (Object.hasOwn(schema, 'const') && !deepEqual(schema.const, value, ctx.budget)) {
    addError(ctx, path, 'const で指定された値と一致しません', required);
  }
}

/**
 * `pattern` を評価する。Issuer 由来の不正・過長・線形時間で評価できない正規表現は違反として報告する。
 *
 * ReDoS 対策の方針: `pattern` はネイティブ `RegExp` に渡さず、バックトラッキングをしない線形時間
 * エンジン（`safe-regex`）で評価する。静的検知は `(a*){10}b` のような迂回形が繰り返し見つかったため
 * 採らない。評価ステップは 1 回の検証全体で共有する予算（`MAX_REGEX_STEPS`）を消費し、
 * 使い切った場合は評価量上限と同じく検証全体を fail-closed にする。いずれの拒否も例外にせず
 * 違反として報告する（黙って通過させない）。パターン本体は message に載せない。
 */
function validatePattern(
  ctx: Context,
  pattern: string,
  value: string,
  path: string,
  required: boolean,
): void {
  try {
    if (!compilePattern(ctx, pattern).test(value, ctx.budget.regex)) {
      addError(ctx, path, 'pattern に一致しません', required);
    }
  } catch (error) {
    addError(ctx, path, patternFailureMessage(ctx, error), required);
  }
}

/** 文字列のコードポイント数を数える（`[...value]` のように長さ分の配列を確保しない）。 */
function codePointLength(value: string): number {
  let count = 0;
  for (const _ of value) {
    count += 1;
  }
  return count;
}

/** 文字列向けキーワード（`minLength` / `maxLength` / `pattern` / `format`）を検証する。 */
export function validateString(
  ctx: Context,
  schema: JsonSchema,
  value: string,
  path: string,
  required: boolean,
): void {
  // 文字列の長さに比例する処理（コードポイント数・`pattern` / `format` の入力走査）を、評価ノード数の
  // 上限（`MAX_EVALUATIONS`）だけでは増幅を止められない（1 MiB の文字列 × `$ref` の多重化）ため、
  // 先に走査量へ前払いする。足りなければ何も評価せず、`exhausted` で検証全体を fail-closed にする。
  if (!consumeScan(ctx.budget, stringScanUnits(value.length))) {
    return;
  }
  // 文字数は Unicode コードポイント単位で数える（サロゲートペアを 1 文字と扱う）。配列は確保しない。
  const length =
    typeof schema.minLength === 'number' || typeof schema.maxLength === 'number'
      ? codePointLength(value)
      : 0;
  if (typeof schema.minLength === 'number' && length < schema.minLength) {
    addError(ctx, path, `文字数が最小長 ${schema.minLength} を下回ります`, required);
  }
  if (typeof schema.maxLength === 'number' && length > schema.maxLength) {
    addError(ctx, path, `文字数が最大長 ${schema.maxLength} を超えます`, required);
  }
  if (typeof schema.pattern === 'string') {
    validatePattern(ctx, schema.pattern, value, path, required);
  }
  const format = schema.format;
  if (typeof format === 'string') {
    const check = FORMAT_CHECKS.get(format);
    if (check !== undefined && !check(value)) {
      addError(ctx, path, `format ${format} の形式ではありません`, required);
    }
  }
}

/** 数値向けキーワード（`minimum` / `maximum` / `exclusive*` / `multipleOf`）を検証する。 */
export function validateNumber(
  ctx: Context,
  schema: JsonSchema,
  value: number,
  path: string,
  required: boolean,
): void {
  if (typeof schema.minimum === 'number' && value < schema.minimum) {
    addError(ctx, path, `最小値 ${schema.minimum} を下回ります`, required);
  }
  if (typeof schema.maximum === 'number' && value > schema.maximum) {
    addError(ctx, path, `最大値 ${schema.maximum} を超えます`, required);
  }
  if (typeof schema.exclusiveMinimum === 'number' && value <= schema.exclusiveMinimum) {
    addError(ctx, path, `${schema.exclusiveMinimum} より大きい必要があります`, required);
  }
  if (typeof schema.exclusiveMaximum === 'number' && value >= schema.exclusiveMaximum) {
    addError(ctx, path, `${schema.exclusiveMaximum} より小さい必要があります`, required);
  }
  const multipleOf = schema.multipleOf;
  if (typeof multipleOf === 'number' && multipleOf > 0 && !isMultipleOf(value, multipleOf)) {
    addError(ctx, path, `${multipleOf} の倍数ではありません`, required);
  }
}

/**
 * `uniqueItems: true` を検証する。要素を正規化した文字数を走査量予算へ計上し、上限を超える配列と
 * 正規化できない要素を含む配列は黙って通過させず違反として報告する。
 */
export function validateUniqueItems(
  ctx: Context,
  value: readonly unknown[],
  path: string,
  required: boolean,
): void {
  try {
    if (hasDuplicateItems(value, ctx.budget)) {
      addError(ctx, path, '要素が重複しています', required);
    }
  } catch {
    // 走査量の超過は `consumeScan` が `exhausted` を立てる。JSON 値でない要素もここへ来る。
    addError(
      ctx,
      path,
      'uniqueItems を評価できません（走査量の上限超過・JSON 値でない要素）',
      required,
    );
  }
}
