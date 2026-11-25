/**
 * termsOfUse エントリの ODRL 規則評価（`terms-of-use.ts` の下位ロジック）。
 *
 * permission / prohibition / obligation の 3 種の規則集合を利用文脈に対して評価し、違反と利用制限を
 * 積み上げる。未知語彙（対象外 `action` / 未知 `leftOperand` / 対応外 `operator`）の倒し方は
 * `ToUCheckOptions` で決まる（既定 fail-open、opt-in で fail-closed）。
 *
 * セキュリティ: 例外 message / context に VC 本文（ToU の値）を含めない。
 */

import {
  coerceSeverity,
  entryIdPrefix,
  evaluateRule,
  extractRestrictions,
  ruleActionScope,
  ruleId,
  type ToURestriction,
  type UsageContext,
} from './odrl.js';
import { isMalformedRule } from './rules.js';
import type { OdrlRule, UnknownVocabularyPolicy } from './types.js';

/** ToU 違反 1 件。 */
export interface ToUViolation {
  /** 違反したルールの識別子。 */
  readonly ruleId: string;
  /** 違反内容の説明。 */
  readonly message: string;
  /** 重大度。`deny` は提示拒否、`warn` は警告のみ。 */
  readonly severity: 'deny' | 'warn';
}

/** 解決済みの評価ポリシー（オプション未指定時は従来どおり fail-open）。 */
export interface ResolvedPolicies {
  /** 評価できない制約（未知 `leftOperand` / 対応外 `operator` / 構造不正）の扱い。 */
  readonly constraint: UnknownVocabularyPolicy;
  /** 評価対象外 `action` を持つルールの扱い。 */
  readonly action: UnknownVocabularyPolicy;
}

/** 評価結果の蓄積先。 */
export interface PolicyAccumulator {
  readonly violations: ToUViolation[];
  readonly restrictions: ToURestriction[];
}

/** ルール 1 件の判定結果。 */
type RuleOutcome =
  /** 評価対象外のため無視する（fail-open）。 */
  | { readonly kind: 'skip' }
  /** 評価できないため deny 違反に倒す（fail-closed）。 */
  | { readonly kind: 'unevaluable'; readonly violation: ToUViolation }
  /** 評価できた（`matched` は全 constraint の合致可否）。 */
  | { readonly kind: 'evaluated'; readonly matched: boolean };

/** 評価不能（未知語彙）を表す `deny` 違反を作る。 */
function unevaluableViolation(id: string, kind: 'action' | 'constraint'): ToUViolation {
  return {
    ruleId: id,
    message:
      kind === 'action'
        ? 'rule action not evaluable (fail-closed)'
        : 'rule constraint not evaluable (fail-closed)',
    severity: 'deny',
  };
}

/** 評価不能（未知語彙）を fail-closed で `deny` 違反に倒す。 */
function unevaluable(id: string, kind: 'action' | 'constraint'): RuleOutcome {
  return { kind: 'unevaluable', violation: unevaluableViolation(id, kind) };
}

/**
 * ルール 1 件を、評価対象かどうかと未知語彙の扱いを含めて判定する。
 *
 * fail-open では `unevaluable` を返さない（未知 `leftOperand` は制約成立、対象外 action は `skip`）。
 *
 * @throws `UsageContext.at` が不正な ISO の場合（`VC_SCHEMA_INVALID` 3002）。VC 本文由来の
 *         `rightOperand` の不正は例外にせず評価不能として扱う（`compareDateTime` 参照）。
 */
function classifyRule(
  rule: OdrlRule,
  id: string,
  context: UsageContext,
  policies: ResolvedPolicies,
): RuleOutcome {
  if (isMalformedRule(rule)) {
    // 規則の形状自体が不正（文字列・数値等）。constraint の構造不正と同じ扱いにする。
    return policies.constraint === 'fail-closed' ? unevaluable(id, 'constraint') : { kind: 'skip' };
  }
  if (ruleActionScope(rule) === 'out-of-scope') {
    return policies.action === 'fail-closed' ? unevaluable(id, 'action') : { kind: 'skip' };
  }
  const evaluation = evaluateRule(rule, context, policies.constraint);
  if (policies.constraint === 'fail-closed' && evaluation.undecidable) {
    return unevaluable(id, 'constraint');
  }
  return { kind: 'evaluated', matched: evaluation.matched };
}

/** prohibition を評価する（合致 = 違反、既定 `deny`）。 */
export function evaluateProhibitions(
  rules: readonly OdrlRule[],
  entryId: string | undefined,
  context: UsageContext,
  policies: ResolvedPolicies,
  out: PolicyAccumulator,
): void {
  rules.forEach((rule, i) => {
    out.restrictions.push(...extractRestrictions(rule, 'prohibition'));
    const id = ruleId(rule, entryId, i, 'prohibition');
    const outcome = classifyRule(rule, id, context, policies);
    if (outcome.kind === 'unevaluable') {
      out.violations.push(outcome.violation);
      return;
    }
    if (outcome.kind === 'skip' || !outcome.matched) {
      return;
    }
    out.violations.push({
      ruleId: id,
      message: 'usage prohibited by termsOfUse',
      severity: coerceSeverity(rule, 'deny'),
    });
  });
}

/**
 * permission を allowlist として評価する。
 *
 * 適用対象の permission が 1 件以上あり、いずれにも合致しなければ `deny`。fail-closed で評価不能な
 * permission があった場合はその旨の `deny` 違反のみを返し、allowlist 違反は重ねて積まない。
 */
export function evaluatePermissions(
  rules: readonly OdrlRule[],
  entryId: string | undefined,
  context: UsageContext,
  policies: ResolvedPolicies,
  out: PolicyAccumulator,
): void {
  const applicable: Array<{ rule: OdrlRule; id: string }> = [];
  // action が判定不能で deny を立てた件数。allowlist 違反の重複積みを防ぐために数える
  // （permission が判定不能で deny になった場合、allowlist 不成立の違反は
  // 重ねて積まない。この規定は constraint 経路と action 経路の両方に無条件で掛かる）。
  let unevaluableCount = 0;
  rules.forEach((rule, i) => {
    const id = ruleId(rule, entryId, i, 'permission');
    if (isMalformedRule(rule)) {
      // 形状不正の permission は allowlist に加えない。fail-closed では評価不能として deny する。
      if (policies.constraint === 'fail-closed') {
        out.violations.push(unevaluableViolation(id, 'constraint'));
        unevaluableCount += 1;
      }
      return;
    }
    if (ruleActionScope(rule) === 'out-of-scope') {
      if (policies.action === 'fail-closed') {
        out.violations.push(unevaluableViolation(id, 'action'));
        unevaluableCount += 1;
      }
      return;
    }
    applicable.push({ rule, id });
  });
  if (applicable.length === 0) {
    return;
  }
  for (const { rule } of applicable) {
    out.restrictions.push(...extractRestrictions(rule, 'permission'));
  }

  let granted = false;
  for (const { rule, id } of applicable) {
    const outcome = classifyRule(rule, id, context, policies);
    if (outcome.kind === 'unevaluable') {
      out.violations.push(outcome.violation);
      unevaluableCount += 1;
      continue;
    }
    if (outcome.kind === 'evaluated' && outcome.matched) {
      granted = true;
      if (policies.constraint === 'fail-open') {
        // fail-open では従来の some() と同じく最初の合致で打ち切る（後続の制約を評価しない）。
        break;
      }
    }
  }
  if (!granted && unevaluableCount === 0) {
    out.violations.push({
      ruleId: `${entryIdPrefix(entryId)}#permission`,
      message: 'usage not permitted by any termsOfUse permission',
      severity: 'deny',
    });
  }
}

/** obligation を評価する（未充足 = 違反、既定 `warn`）。 */
export function evaluateObligations(
  rules: readonly OdrlRule[],
  entryId: string | undefined,
  context: UsageContext,
  policies: ResolvedPolicies,
  out: PolicyAccumulator,
): void {
  rules.forEach((rule, i) => {
    out.restrictions.push(...extractRestrictions(rule, 'obligation'));
    const id = ruleId(rule, entryId, i, 'obligation');
    const outcome = classifyRule(rule, id, context, policies);
    if (outcome.kind === 'unevaluable') {
      out.violations.push(outcome.violation);
      return;
    }
    if (outcome.kind === 'skip' || outcome.matched) {
      return;
    }
    out.violations.push({
      ruleId: id,
      message: 'obligation not fulfilled',
      severity: coerceSeverity(rule, 'warn'),
    });
  });
}
