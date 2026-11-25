/**
 * DIF Presentation Exchange v2 の Presentation Definition 評価。
 *
 * 本モジュールは Verifier の Presentation Definition を保持クレデンシャル集合に対して評価し、
 * 候補を列挙する **純粋関数** を提供する（ネットワーク・署名検証・暗号プリミティブは伴わない）。
 * 選択的開示（BBS+ 等）の実行は本モジュールの責務ではない。
 *
 * 評価ロジック:
 * - `format`: 指定時は、そのキー（`jwt_vc_json` / `dc+sd-jwt` / `vc+sd-jwt` / `ldp_vc`）のいずれかが
 *   クレデンシャルの format と一致すること。SDK 非対応の format（`mso_mdoc` 等）しか要求しない
 *   記述子は `unsatisfiable` として、どのクレデンシャルにもマッチさせない。
 * - `constraints.fields[].path`: JSONPath 式の候補配列を**先頭から順に**試し、最初に解決できた値を
 *   採用する（DIF PEx v2 の複数 path 候補セマンティクス）。走査量は予算（`MAX_PATH_READS`）で
 *   抑え、超過した記述子 × クレデンシャルは不一致（fail-closed）にする。
 * - `constraints.fields[].filter`: 解決した値が JSON Schema 風フィルタ（`filter.ts`）を満たすこと。
 *   `pattern` は線形時間エンジンで、ネイティブ `RegExp`（`u` なし）と同じ ECMA-262 Annex B 互換の
 *   構文として評価する（ReDoS 対策。後方参照・先読みを含むもの / 予算超過は不一致）。
 * - `constraints.fields[].optional`: `true` なら値が解決できなくても不一致にしない。
 *
 * セキュリティ上の注意:
 * - 例外メッセージ・`context` にクレーム値や VC 本文を含めない。
 */

import { JSONPath } from 'jsonpath-plus';
import type { CredentialMatch, QueryableCredential } from '../auth/dcql/dcql.js';
import { consumeWork } from '../primitives/work-budget.js';
import { ownProperty } from '../prototype-safety/own-property.js';
import { createPexBudget, type PexBudget } from './budget.js';
import type { Field, InputDescriptor, PresentationDefinition } from './definition.js';
import { matchesFilter } from './filter.js';
import { expressionSandbox } from './guarded-eval.js';
import { guardedPathScript } from './guarded-script.js';
import { ensureBoundedJsonPathCache } from './jsonpath-cache.js';
import { rejectTooManyInputDescriptors, rejectTooManyMatches } from './limits.js';
import {
  budgetedView,
  expressionWeight,
  FIELD_EVALUATION_COST,
  PATH_CALL_COST,
  type PathBudget,
  PathBudgetExceededError,
} from './path-budget.js';

/** `FormatRequirement` に現れ得る format キー。 */
const FORMAT_REQUIREMENT_KEYS: readonly string[] = [
  'jwt_vc_json',
  'dc+sd-jwt',
  'vc+sd-jwt',
  'ldp_vc',
];

/**
 * 単一 JSONPath 式でクレーム object を辿る。解決できなければ `{ found: false }`。
 * 走査量の予算を使い切った場合は `budget.exhausted` が立つ（呼び出し側が不一致にする）。
 */
function resolveJsonPath(
  claims: Readonly<Record<string, unknown>>,
  path: string,
  budget: PathBudget,
): { found: boolean; value: unknown } {
  // `JSONPath()` 1 回ごとに固定費を計上する。読み出しの無い path（`$^` / `$~` / `$`）でも予算が減る。
  if (!consumeWork(budget, PATH_CALL_COST)) {
    return { found: false, value: undefined };
  }
  // `jsonpath-plus` の静的キャッシュはリクエストをまたいで無制限に増えるため、評価の前に上限つきへ差し替える。
  ensureBoundedJsonPathCache();
  // 式は `jsonpath-plus` の safe 評価器を許可リストで包んだ `guardedPathScript()` で評価する。素の
  // `eval: 'safe'` は式内のメソッド呼び出し（`@.padStart(5e8,…)` 等）を実行でき、予算が効かない。
  // Presentation Definition は Verifier 由来の非信頼入力であり、native eval も使わせてはならない。
  let results: unknown[];
  try {
    results = JSONPath({
      path,
      json: budgetedView(claims, budget, expressionWeight(path)),
      wrap: true,
      eval: guardedPathScript(),
      // 式の評価器が文字列の走査量を前払いする予算。式の識別子からは到達できない Symbol キー。
      sandbox: expressionSandbox(budget),
    }) as unknown[];
  } catch (error) {
    if (error instanceof PathBudgetExceededError) {
      return { found: false, value: undefined };
    }
    // 構文不正・評価不能な式（`$[?(@.x==1` / `$[(1+1)]` / `$[?(@.__proto__)]` 等）で jsonpath-plus は
    // 素の Error / TypeError を投げる。生の例外で他クレデンシャルの評価まで中断させず、
    // その path は解決できなかった（fail-closed）ものとして扱う。例外の内容（クレーム値を含み得る）は破棄する。
    return { found: false, value: undefined };
  }
  return results.length === 0
    ? { found: false, value: undefined }
    : { found: true, value: results[0] };
}

/** `path` 候補を先頭から順に試し、最初に解決できた `{ path, value }` を返す。 */
function resolveFirstPath(
  claims: Readonly<Record<string, unknown>>,
  paths: readonly string[],
  budget: PathBudget,
): { path: string; value: unknown } | undefined {
  for (const path of paths) {
    const { found, value } = resolveJsonPath(claims, path, budget);
    if (found) {
      return { path, value };
    }
  }
  return undefined;
}

/**
 * 単一 `Field` を評価する。
 *
 * @returns 一致した path（結果の `matchedClaims` に載せる）。`optional` で値が無い場合は
 *   `{ matched: true, path: undefined }`。不一致は `{ matched: false }`。
 */
function evaluateField(
  field: Field,
  claims: Readonly<Record<string, unknown>>,
  budget: PexBudget,
): { matched: boolean; path?: string } {
  // フィールド 1 件の評価は、path が何件・解決できるかに関わらず固定費を計上する。
  if (!consumeWork(budget.paths, FIELD_EVALUATION_COST)) {
    return { matched: false };
  }
  const resolved = resolveFirstPath(claims, field.path, budget.paths);
  if (budget.paths.exhausted) {
    // 走査量の超過は「値が無い」ではなく評価不能。`optional` でも通さず不一致にする（fail-closed）。
    return { matched: false };
  }
  if (resolved === undefined) {
    // `optional` は own 限定（`Object.prototype.optional = true` で必須フィールドが任意扱いになり、
    // 値が無い VC が入力記述子を満たしてしまうのを防ぐ）。
    return { matched: ownProperty<boolean>(field, 'optional') === true };
  }
  const filter = ownProperty<NonNullable<Field['filter']>>(field, 'filter');
  if (filter === undefined) {
    return { matched: true, path: resolved.path };
  }
  try {
    if (!matchesFilter(resolved.value, filter, budget)) {
      return { matched: false };
    }
  } catch (error) {
    // `const` / `enum` の比較はクレームのビューを読むため、走査量の超過（`PathBudgetExceededError`）や
    // 深い入れ子によるスタック枯渇（`RangeError`）が起こり得る。評価不能として不一致にする。
    if (error instanceof PathBudgetExceededError || error instanceof RangeError) {
      return { matched: false };
    }
    throw error;
  }
  // 比較の途中で予算を使い切った場合も、その結果は信用せず不一致にする。
  if (budget.paths.exhausted || budget.scan.exhausted) {
    return { matched: false };
  }
  return { matched: true, path: resolved.path };
}

/** 要求 format をクレデンシャルの format と突き合わせる（未指定なら format を問わない）。 */
function matchesFormat(descriptor: InputDescriptor, credential: QueryableCredential): boolean {
  const format = ownProperty<NonNullable<InputDescriptor['format']>>(descriptor, 'format');
  if (format === undefined) {
    return true;
  }
  if (ownProperty<boolean>(format, 'unsatisfiable') === true) {
    // SDK 非対応の format（`mso_mdoc` 等）しか要求していない。どの VC も満たせない。
    return false;
  }
  const requested = FORMAT_REQUIREMENT_KEYS.filter((key) => Object.hasOwn(format, key));
  // キーが 1 つも無い `format: {}` は制約なしとみなす。
  return requested.length === 0 || requested.includes(credential.format);
}

/** 単一 Input Descriptor に対し単一クレデンシャルがマッチするか評価する。 */
function evaluateInputDescriptor(
  descriptor: InputDescriptor,
  credential: QueryableCredential,
  budget: PexBudget,
): CredentialMatch | undefined {
  // 記述子 × 保持 VC の組 1 件ごとに 1 単位。フィールドを持たない記述子でも評価量が予算に現れる。
  if (!consumeWork(budget.paths, 1)) {
    return undefined;
  }
  if (!matchesFormat(descriptor, credential)) {
    return undefined;
  }

  const matchedClaims: string[] = [];
  for (const field of descriptor.constraints.fields) {
    const result = evaluateField(field, credential.claims, budget);
    if (!result.matched) {
      return undefined;
    }
    if (result.path !== undefined) {
      matchedClaims.push(result.path);
    }
  }

  return {
    credentialId: credential.id,
    queryId: descriptor.id,
    matchedClaims,
  };
}

/**
 * Presentation Definition を保持クレデンシャル集合に対して評価し、マッチ候補を返す。
 *
 * 各 Input Descriptor について、format / fields をすべて満たすクレデンシャルを候補として
 * 列挙する。1 記述子に複数候補がある場合は全件返す（最終選択は UI / 呼び出し側。`evaluateDcql`
 * と同じ方針）。
 *
 * `evaluateDcql` と同様に、format / vct / クレームを正規化した `QueryableCredential` を評価する。
 * 正規化は `auth/matcher.ts` が担うため、評価時に元の署名形式を解釈する必要はない。
 *
 * 要求 format が SDK 非対応でも例外は投げず、その Input Descriptor の候補から外すだけである
 * （`evaluateDcql` の `8050` 即時 throw とは異なる）。Presentation Definition は複数記述子を
 * 持ち得るため、1 つが非対応でも残りの評価は継続すべきだからである。
 *
 * 予算（正規表現ステップ・JSONPath 走査量）は呼び出し 1 回で新規に作る。保持 VC を 1 件ずつ
 * 評価する呼び出し側は `evaluatePresentationDefinitionWithBudget` へ共有予算を渡す。
 *
 * @param pd パース済み Presentation Definition。
 * @param credentials 正規化済み保持クレデンシャル。
 * @returns マッチ結果の配列（記述子 × クレデンシャルの直積のうちマッチしたもの）。
 * @throws 記述子数が `MAX_INPUT_DESCRIPTORS`、マッチ件数が `MAX_PEX_MATCHES` を超える場合
 *   （VericertsError、code `8030`、`context.reason: 'too_many_input_descriptors' | 'too_many_matches'`）。
 */
export function evaluatePresentationDefinition(
  pd: PresentationDefinition,
  credentials: readonly QueryableCredential[],
): CredentialMatch[] {
  return evaluatePresentationDefinitionWithBudget(pd, credentials, createPexBudget());
}

/**
 * {@link evaluatePresentationDefinition} の共有予算版（SDK 内部用。公開 API ではない）。
 *
 * 予算は記述子 × クレデンシャル × フィールドの全体で消費され、呼び出しをまたいで共有できる。
 * 使い切った後の評価は不一致（fail-closed）になる。
 */
export function evaluatePresentationDefinitionWithBudget(
  pd: PresentationDefinition,
  credentials: readonly QueryableCredential[],
  budget: PexBudget,
): CredentialMatch[] {
  // 手組みの PD（`parsePresentationDefinition` を通っていないもの）に備え、評価前に記述子数を再検査する。
  rejectTooManyInputDescriptors(pd.input_descriptors);
  const matches: CredentialMatch[] = [];
  for (const descriptor of pd.input_descriptors) {
    for (const credential of credentials) {
      // 予算（JSONPath 走査量・`const` / `enum` の走査量）が尽きた後は、以降の記述子 × VC の組を評価しない。
      // 残りは不一致（fail-closed）で、尽きた予算のまま同じ組を回し続けない。
      if (budget.paths.exhausted || budget.scan.exhausted) {
        return matches;
      }
      const match = evaluateInputDescriptor(descriptor, credential, budget);
      if (match !== undefined) {
        rejectTooManyMatches(matches.length);
        matches.push(match);
      }
    }
  }
  return matches;
}
