/**
 * オブジェクトの各キーを、どの部分スキーマで検証するかへ割り当てる（`properties` /
 * `patternProperties` / `additionalProperties`）。
 *
 * 本ファイルは公開バレル（`index.ts`）から re-export しない内部実装。
 *
 * Draft 2020-12 ではこの 3 キーワードは独立に働く。あるキーは `properties` に宣言があれば
 * その部分スキーマで、`patternProperties` の正規表現に一致すればその部分スキーマで
 * （複数に一致すればそのすべてで）検証され、**どちらにも当たらなかったキーだけ**が
 * `additionalProperties` の対象になる。`patternProperties` を無視すると一致するキーまで
 * 「追加プロパティ」と数えてしまい、スキーマに適合するクレデンシャルへ偽の違反を報告する。
 *
 * セキュリティ上の注意: `patternProperties` のキーは Issuer 由来の
 * 正規表現なので、`pattern` と同じく線形時間エンジン（`safe-regex`）で評価する。
 * 評価できない正規表現が 1 つでもあると「どのキーが追加プロパティなのか」を決められないため、
 * `additionalProperties` の判定は行わず（偽の違反を作らない）、評価できなかったこと自体を
 * 呼び出し側が違反として報告できるよう {@link ObjectPropertiesPlan.patternUnusable} で返す。
 */

import type { SafeRegex } from '../../primitives/safe-regex/index.js';
import { isPlainObject } from '../object-guards.js';
import {
  addError,
  type CompiledPatternProperties,
  type Context,
  compilePattern,
  consumeScan,
  escapePointer,
  patternFailureMessage,
  stringScanUnits,
} from './internals.js';
import type { JsonSchema } from './types.js';

/** 1 キーに適用する部分スキーマ。同一キーが複数の割り当てを持つことがある。 */
export interface PropertyAssignment {
  /** インスタンス側のプロパティ名（JSON Pointer へはエスケープして埋める）。 */
  readonly key: string;
  /** そのキーに適用する部分スキーマ（未検証の生 JSON）。 */
  readonly schema: unknown;
}

/** オブジェクトのプロパティ検証計画。 */
export interface ObjectPropertiesPlan {
  /** 各キーに適用する部分スキーマの割り当て。 */
  readonly assignments: readonly PropertyAssignment[];
  /** `additionalProperties: false` により拒否されたキー。 */
  readonly rejectedKeys: readonly string[];
  /** `patternProperties` に評価できない正規表現があり、追加プロパティを判定しなかったか。 */
  readonly patternUnusable: boolean;
}

/** 配列を除く素の object としてキーワード値を読む（それ以外は「未指定」と同じ扱い）。 */
function toSchemaMap(value: unknown): Record<string, unknown> {
  return isPlainObject(value) ? value : {};
}

/**
 * `patternProperties` の正規表現をコンパイルする（`patternProperties` オブジェクトごとに 1 回）。
 *
 * 過長・線形時間で評価できない構文・構文不正なものは黙って通過させず、`unusable` として
 * 呼び出し側へ知らせる。結果は検証内でキャッシュし、オブジェクトのたびに全エントリを
 * 再コンパイル・再走査させない。
 */
function compilePatternProperties(ctx: Context, schema: JsonSchema): CompiledPatternProperties {
  const raw = schema.patternProperties;
  if (!isPlainObject(raw)) {
    return { matchers: [], unusable: false };
  }
  const cached = ctx.compiled.patternProperties.get(raw);
  if (cached !== undefined) {
    return cached;
  }
  const matchers: { regex: SafeRegex; schema: unknown }[] = [];
  let unusable = false;
  const entries = Object.entries(raw);
  // スキーマ側エントリ数を前払いする（検証 1 回内ではオブジェクトごとに 1 回だけ）。
  // 足りなければコンパイルせず、`exhausted` で検証全体を fail-closed にする。
  if (!consumeScan(ctx.budget, entries.length)) {
    return { matchers: [], unusable: true };
  }
  for (const [source, sub] of entries) {
    try {
      matchers.push({ regex: compilePattern(ctx, source), schema: sub });
    } catch (error) {
      patternFailureMessage(ctx, error);
      unusable = true;
    }
  }
  const compiled = { matchers, unusable };
  ctx.compiled.patternProperties.set(raw, compiled);
  return compiled;
}

/** キーが正規表現に一致するか。評価量の上限超過は `exhausted` を立てて `undefined`（判定不能）を返す。 */
function matchesKey(ctx: Context, regex: SafeRegex, key: string): boolean | undefined {
  try {
    return regex.test(key, ctx.budget.regex);
  } catch (error) {
    patternFailureMessage(ctx, error);
    return undefined;
  }
}

/**
 * このノード自身の `required` を検証する（欠落は常に必須違反）。
 *
 * 子の必須分類に使うキー集合は `required-keys.ts` がスキーマグラフ全体から集める。ここは「欠落の報告」だけを担う。
 * 配列の長さを走査量予算へ前払いし、予算が足りなければ走査せず、`exhausted` により検証全体が fail-closed になる。
 */
export function validateRequired(
  ctx: Context,
  schema: JsonSchema,
  value: Record<string, unknown>,
  path: string,
): void {
  const raw = schema.required;
  if (!Array.isArray(raw) || !consumeScan(ctx.budget, raw.length)) {
    return;
  }
  for (const key of raw) {
    if (typeof key !== 'string') {
      continue;
    }
    if (!Object.hasOwn(value, key)) {
      // 違反 path の生成（`escapePointer`）はキー長に比例するため、巨大な必須キー × 分岐の増幅を
      // 走査量で止める。尽きたら以降は組み立てず、`exhausted` で fail-closed にする。
      if (!consumeScan(ctx.budget, stringScanUnits(key.length))) {
        break;
      }
      // required キーワード違反は常に「必須属性の違反」として分類する（FO-4 の対象外）。
      addError(ctx, `${path}/${escapePointer(key)}`, '必須プロパティが存在しません', true);
    }
  }
}

/**
 * オブジェクトのキーを部分スキーマへ割り当てる。
 *
 * @param ctx 検証文脈（正規表現評価の共有予算を持つ）。
 * @param schema 対象ノードのスキーマ。`properties` / `patternProperties` /
 *               `additionalProperties` のみを読む。
 * @param keys インスタンスが自身のプロパティとして持つキー。
 * @returns 検証計画（割り当て・拒否キー・`patternProperties` を評価できたか）。
 */
export function planObjectProperties(
  ctx: Context,
  schema: JsonSchema,
  keys: readonly string[],
): ObjectPropertiesPlan {
  const properties = toSchemaMap(schema.properties);
  const { matchers, unusable: compileFailed } = compilePatternProperties(ctx, schema);
  let unusable = compileFailed;
  // 正規表現の予算切れ。以降はキーごとの一致判定を打ち切る（パターン数 × キー数の空回りを防ぐ）。
  let budgetSpent = false;
  const additional = schema.additionalProperties;
  const assignments: PropertyAssignment[] = [];
  const rejectedKeys: string[] = [];

  for (const key of keys) {
    let covered = false;
    if (Object.hasOwn(properties, key)) {
      assignments.push({ key, schema: properties[key] });
      covered = true;
    }
    for (const matcher of matchers) {
      if (budgetSpent) {
        break;
      }
      const matched = matchesKey(ctx, matcher.regex, key);
      if (matched === undefined) {
        unusable = true;
        budgetSpent = true;
      } else if (matched) {
        assignments.push({ key, schema: matcher.schema });
        covered = true;
      }
    }
    if (covered || additional === undefined || unusable) {
      continue;
    }
    if (additional === false) {
      rejectedKeys.push(key);
    } else if (typeof additional === 'object' && additional !== null) {
      assignments.push({ key, schema: additional });
    }
  }
  return { assignments, rejectedKeys, patternUnusable: unusable };
}
