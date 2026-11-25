/**
 * JSON Schema（Draft 2020-12 サブセット）バリデータ本体。
 *
 * W3C VC の `credentialSchema` と SD-JWT VC の Type Metadata に使用する。
 * Issuer が配布するリモートスキーマを、JavaScript の動的コード生成なしで検証する。
 * これにより `unsafe-eval` を許可しない Manifest V3 の CSP 下でも評価できる。
 *
 * **対応キーワード**（これ以外は JSON Schema の既定どおり**無視**する = 制約なしとして扱う）:
 *
 * | 分類         | キーワード                                                                    |
 * | ------------ | ----------------------------------------------------------------------------- |
 * | 共通         | `type` / `enum` / `const` / `$ref`（ローカル JSON Pointer のみ）               |
 * | 論理         | `allOf` / `anyOf` / `oneOf` / `not`                                            |
 * | オブジェクト | `properties` / `patternProperties` / `required` / `additionalProperties` / `minProperties` / `maxProperties` |
 * | 配列         | `items` / `prefixItems` / `minItems` / `maxItems` / `uniqueItems`              |
 * | 文字列       | `minLength` / `maxLength` / `pattern` / `format`                               |
 * | 数値         | `minimum` / `maximum` / `exclusiveMinimum` / `exclusiveMaximum` / `multipleOf` |
 *
 * `$ref` はローカル JSON Pointer のみ解決する。リモート `$ref`（`https://...`）と解決不能な
 * 参照は違反として報告する（黙って通過させない）。Draft 2020-12 の `$ref` は**兄弟キーワードを
 * 上書きしない**ため、参照先を検証したうえで同ノードの他キーワードも続けて評価する。
 *
 * セキュリティ上の注意:
 * - `message` にインスタンスの値（VC のクレーム値 = PII を含み得る）を埋め込まない。位置は
 *   `path`（JSON Pointer）でのみ示す。
 * - スキーマは Issuer が配布するリモート文書 = 攻撃者が影響し得る入力。`MAX_DEPTH` に加えて
 *   評価ノード数の総量上限（`MAX_EVALUATIONS`）を課し、`anyOf` / `oneOf` / `not` の分岐評価に
 *   よる指数爆発（DoS）を防ぐ。打ち切った場合は黙って適合扱いにせず違反として報告する。
 */

import {
  addError,
  CHARS_PER_SCAN_UNIT,
  type Context,
  consumeEvaluation,
  consumeScan,
  createCompileCache,
  type EvaluationBudget,
  escapePointer,
  MAX_DEPTH,
  MAX_EVALUATIONS,
  MAX_REGEX_STEPS,
  MAX_SCAN_UNITS,
} from './internals.js';
import { planObjectProperties, validateRequired } from './object-properties.js';
import { ownKeysOf } from './own-keys.js';
import { resolveRefCharged } from './ref.js';
import { type RequiredGroup, requiredKeysOfGroup } from './required-keys.js';
import {
  validateCore,
  validateNumber,
  validateString,
  validateUniqueItems,
} from './scalar-keywords.js';
import type { JsonSchema, SchemaValidationResult } from './types.js';

/**
 * 子スキーマを別バッファで試行し、適合したかどうかだけを返す（`anyOf` 等の分岐判定用）。違反バッファのみ分離し、
 * 評価ノード数の残量は親と共有する（分岐ごとにリセットすると総量上限が効かず、指数爆発を止められない）。
 */
function passes(ctx: Context, schema: unknown, value: unknown, depth: number): boolean {
  const probe: Context = { ...ctx, errors: [], probe: true };
  validateNode(probe, schema, value, '', false, depth);
  return probe.errors.length === 0;
}

/** オブジェクト向けキーワードを検証する。 */
function validateObject(
  ctx: Context,
  schema: JsonSchema,
  value: Record<string, unknown>,
  path: string,
  required: boolean,
  depth: number,
  group: RequiredGroup,
): void {
  // 必須キー集合の収集（前払い）か `required` の前払いで予算を使い切ったら、キー列挙（O(K)）へ進まない。
  const groupRequired = requiredKeysOfGroup(ctx, group);
  validateRequired(ctx, schema, value, path);
  if (groupRequired === undefined || ctx.budget.exhausted) {
    return;
  }

  // インスタンスのキー列挙は `allOf` / `$ref` の多重化で繰り返させないよう計上し、キー長に
  // 比例する `escapePointer` も文字数を前払いする。列挙自体はオブジェクトごとに 1 回。
  const { keys, chars: keyChars } = ownKeysOf(ctx.budget, value);
  if (!consumeScan(ctx.budget, keys.length + Math.floor(keyChars / CHARS_PER_SCAN_UNIT))) {
    return;
  }
  if (typeof schema.minProperties === 'number' && keys.length < schema.minProperties) {
    addError(ctx, path, `プロパティ数が最小 ${schema.minProperties} を下回ります`, required);
  }
  if (typeof schema.maxProperties === 'number' && keys.length > schema.maxProperties) {
    addError(ctx, path, `プロパティ数が最大 ${schema.maxProperties} を超えます`, required);
  }

  // どのキーをどの部分スキーマで検証するかは `object-properties.ts` が決める
  // （`patternProperties` に一致するキーは `additionalProperties` の対象外）。
  const plan = planObjectProperties(ctx, schema, keys);
  if (plan.patternUnusable) {
    // 評価できない正規表現を黙って通過させない。正規表現本体は message に載せない。
    addError(ctx, path, 'patternProperties の正規表現を評価できません', required);
  }
  for (const key of plan.rejectedKeys) {
    addError(ctx, `${path}/${escapePointer(key)}`, '追加プロパティは許可されていません', required);
  }
  for (const { key, schema: sub } of plan.assignments) {
    // 予算切れ後は残りのキーのパス組み立て（`escapePointer`）も評価もしない。
    if (ctx.budget.exhausted) {
      return;
    }
    // 親の required に載っているプロパティ配下の違反は「必須属性の違反」として伝播させる。
    validateNode(
      ctx,
      sub,
      value[key],
      `${path}/${escapePointer(key)}`,
      groupRequired.has(key),
      depth + 1,
    );
  }
}

/** 配列向けキーワードを検証する。 */
function validateArray(
  ctx: Context,
  schema: JsonSchema,
  value: readonly unknown[],
  path: string,
  required: boolean,
  depth: number,
): void {
  if (typeof schema.minItems === 'number' && value.length < schema.minItems) {
    addError(ctx, path, `要素数が最小 ${schema.minItems} を下回ります`, required);
  }
  if (typeof schema.maxItems === 'number' && value.length > schema.maxItems) {
    addError(ctx, path, `要素数が最大 ${schema.maxItems} を超えます`, required);
  }
  if (schema.uniqueItems === true) {
    validateUniqueItems(ctx, value, path, required);
  }

  // `prefixItems` のスキーマ側配列長を前払いする。足りなければ走査せず fail-closed。
  const prefixItems = Array.isArray(schema.prefixItems) ? schema.prefixItems : [];
  if (!consumeScan(ctx.budget, prefixItems.length)) {
    return;
  }
  const prefixCount = Math.min(prefixItems.length, value.length);
  for (let i = 0; i < prefixCount && !ctx.budget.exhausted; i += 1) {
    validateNode(ctx, prefixItems[i], value[i], `${path}/${i}`, required, depth + 1);
  }

  const items = schema.items;
  if (typeof items === 'object' && items !== null) {
    for (let i = prefixItems.length; i < value.length && !ctx.budget.exhausted; i += 1) {
      validateNode(ctx, items, value[i], `${path}/${i}`, required, depth + 1);
    }
  } else if (items === false && value.length > prefixItems.length) {
    addError(ctx, path, 'prefixItems を超える要素は許可されていません', required);
  }
}

/**
 * 論理結合キーワード（`allOf` / `anyOf` / `oneOf` / `not`）を検証する。
 *
 * `anyOf` / `oneOf` / `not` の失敗はこのノード自身の違反として記録し、**常に必須違反**（`required: true`）にする。
 * 「いずれかの形を満たすこと」自体が構造制約で、Issuer は `{"oneOf":[{"required":["a"]},{"required":["b"]}]}` のように
 * 必須クレームをこの語彙で表現できる。親の `required` フラグ（ルート直下では常に `false`）で記録すると、
 * このイディオムだけで必須制約が FO-4 の警告通過に落ちる。
 *
 * `allOf` だけは親の `required` をそのまま伝播する（同じノードへ展開するのと等価な透過的連言で、違反は部分スキーマ側で
 * 記録される）。必須へ格上げすると、任意プロパティを `allOf` で包んだだけのスキーマで FO-4 が効かなくなる。
 */
function validateLogic(
  ctx: Context,
  schema: JsonSchema,
  value: unknown,
  path: string,
  required: boolean,
  depth: number,
  group: RequiredGroup,
): void {
  // スキーマ側配列の要素数を前払いする。足りなければ走査せず、`exhausted` で検証全体を fail-closed にする。
  if (Array.isArray(schema.allOf) && consumeScan(ctx.budget, schema.allOf.length)) {
    for (const sub of schema.allOf) {
      validateNode(ctx, sub, value, path, required, depth + 1, group);
    }
  }
  if (
    Array.isArray(schema.anyOf) &&
    consumeScan(ctx.budget, schema.anyOf.length) &&
    !schema.anyOf.some((sub) => passes(ctx, sub, value, depth + 1))
  ) {
    addError(ctx, path, 'anyOf のいずれの条件も満たしません', true);
  }
  if (Array.isArray(schema.oneOf) && consumeScan(ctx.budget, schema.oneOf.length)) {
    const matched = schema.oneOf.filter((sub) => passes(ctx, sub, value, depth + 1)).length;
    if (matched !== 1) {
      addError(ctx, path, `oneOf に適合する条件が ${matched} 件です`, true);
    }
  }
  // `not` は boolean スキーマも取り得る（`not: true` = 常に不適合、`not: false` = 常に適合）。
  if (
    (typeof schema.not === 'boolean' || (typeof schema.not === 'object' && schema.not !== null)) &&
    passes(ctx, schema.not, value, depth + 1)
  ) {
    addError(ctx, path, 'not で禁止された条件に適合します', true);
  }
}

/** 1 ノードを検証する。 */
function validateNode(
  ctx: Context,
  schema: unknown,
  value: unknown,
  path: string,
  required: boolean,
  depth: number,
  inheritedGroup?: RequiredGroup,
): void {
  // 予算切れ後は何も評価しない（残りの評価ノード数ぶん O(K) 処理を空回りさせない）。
  // 違反はルートで 1 件記録する。boolean スキーマ等の早期 return も 1 単位は消費する。
  if (ctx.budget.exhausted) {
    return;
  }
  if (!consumeEvaluation(ctx.budget)) {
    addError(ctx, path, '評価量が上限に達したため評価を打ち切りました', required);
    return;
  }
  // boolean スキーマ（Draft 2020-12）: true = 常に適合、false = 常に不適合。
  if (schema === true) {
    return;
  }
  if (schema === false) {
    addError(ctx, path, 'スキーマが false のため常に不適合です', required);
    return;
  }
  if (typeof schema !== 'object' || schema === null || Array.isArray(schema)) {
    // スキーマとして解釈できないノードは制約なしとして扱う。
    return;
  }
  if (depth > MAX_DEPTH) {
    addError(ctx, path, 'スキーマのネストが深すぎるため評価を打ち切りました', required);
    return;
  }
  const node = schema as JsonSchema;
  // `$ref` / `allOf` で同じインスタンス位置へ展開された先は、入口のノードと必須キーの集合を共有する。
  const group: RequiredGroup = inheritedGroup ?? { entry: node };

  const ref = node.$ref;
  if (typeof ref === 'string') {
    // 解決コスト（参照長に比例）は走査量へ前払いし、長すぎる参照は解決しない。
    const resolved = resolveRefCharged(ctx.root, ref, ctx.budget);
    if (resolved === undefined) {
      // リモート $ref・解決不能な $ref・長さ/予算超過の $ref は黙って通過させない。
      addError(ctx, path, '$ref を解決できません（ローカル参照のみ・長さ上限あり）', required);
      return;
    }
    // Draft 2020-12 の `$ref` は兄弟キーワードを上書きしない。参照先を検証したうえで
    // フォールスルーし、同ノードの他キーワード（`required` / `additionalProperties` 等）も
    // 続けて評価する（silent under-validation の防止）。
    validateNode(ctx, resolved, value, path, required, depth + 1, group);
    if (ctx.budget.exhausted) {
      return;
    }
  }

  validateCore(ctx, node, value, path, required);
  validateLogic(ctx, node, value, path, required, depth, group);

  if (typeof value === 'string') {
    validateString(ctx, node, value, path, required);
  } else if (typeof value === 'number') {
    validateNumber(ctx, node, value, path, required);
  } else if (Array.isArray(value)) {
    validateArray(ctx, node, value, path, required, depth);
  } else if (typeof value === 'object' && value !== null) {
    validateObject(ctx, node, value as Record<string, unknown>, path, required, depth, group);
  }
}

/**
 * インスタンスを JSON Schema（Draft 2020-12 サブセット）で検証する。
 *
 * 例外を投げず、違反を `errors` にまとめて返す。
 * 深さ上限・評価量上限で打ち切った場合も例外にせず違反として報告する。
 * 各違反の `required` により、必須属性の違反（fail-closed 相当）と任意属性の違反
 * （FO-4 の警告通過の対象）を呼び出し側が区別できる。分類の規則は
 * `types.ts` の `SchemaError.required` に集約してある。**ルート（`path` が空文字列）の違反は
 * インスタンス全体の構造がスキーマと矛盾していることを意味するため常に必須違反**であり、
 * 任意扱いにすると `credentialSubject` の型が丸ごと食い違う VC まで警告通過してしまう。
 *
 * @param schema JSON Schema 文書。`$ref` はこの文書内のローカル参照のみ解決する。
 * @param instance 検証対象の値。
 * @returns 検証結果（`valid` と、違反があれば `errors`）。
 */
export function validateAgainstSchema(
  schema: JsonSchema,
  instance: unknown,
): SchemaValidationResult {
  const budget: EvaluationBudget = {
    remaining: MAX_EVALUATIONS,
    exhausted: false,
    regex: { remaining: MAX_REGEX_STEPS },
    scanRemaining: MAX_SCAN_UNITS,
  };
  const ctx: Context = { errors: [], root: schema, budget, compiled: createCompileCache() };
  // ルートには「親の required 配列」が存在しない。`false` を渡すのは配下へ必須フラグを
  // ばら撒かないためで、ルート自身の違反は `addError` が空 path として必須へ格上げする。
  validateNode(ctx, schema, instance, '', false, 0);
  if (budget.exhausted) {
    // 分岐（`anyOf` / `not` 等）の試行内で使い切った場合その違反は破棄されるため、ルートにも
    // 必ず 1 件記録する。DoS で打ち切った検証結果を fail-open（適合）にしない。
    // 違反件数が上限に達していても必ず残す（`addError` は上限超過分を捨てるため直接積む）。
    ctx.errors.push({
      path: '',
      message: '評価量が上限に達したため評価を打ち切りました',
      required: true,
    });
  }
  return ctx.errors.length === 0 ? { valid: true } : { valid: false, errors: ctx.errors };
}
