/**
 * ODRL 風ポリシー評価エンジン（termsOfUse 評価の下位ロジック）。
 *
 * `terms-of-use.ts` から利用され、単一ルール（permission / prohibition / obligation）の適用可否と
 * 制約（constraint: purpose / dateTime / spatial）の合致を判定する純粋関数群を提供する。
 *
 * セキュリティ: 例外 message / context に VC 本文（ToU の値）を含めない。
 */

import { ownProperty } from '../../prototype-safety/own-property.js';
import { isPlainObject as isRecord } from '../object-guards.js';
import { compareDateTime, compareString } from './operators.js';
import type { OdrlConstraint, OdrlRule, UnknownVocabularyPolicy } from './types.js';

/** 提示先・目的・時刻・地域の利用文脈。 */
export interface UsageContext {
  /** 提示先 Verifier 識別子。 */
  readonly verifierId: string;
  /** 提示目的（ODRL `purpose` 制約との照合に使う）。 */
  readonly purpose?: string;
  /** 利用地域（ISO 3166-1 alpha-2）。ODRL `spatial` 制約との照合に使う。 */
  readonly geolocation?: string;
  /** 利用時刻（ISO 8601）。既定は現在時刻。ODRL `dateTime` 制約との照合に使う。 */
  readonly at?: string;
}

/** ToU から抽出した利用制限（UI 表示用）。 */
export interface ToURestriction {
  /** 制限の種類。constraint の `leftOperand` をそのまま載せる（既知は `purpose` / `dateTime` / `spatial`）。 */
  readonly kind: string;
  /** 表示用の説明（`<prohibition|permission|obligation>: <leftOperand> <operator> <rightOperand>`）。 */
  readonly description: string;
}

/** `object-guards.ts` の再エクスポート。既存の import パス（`./odrl.js` 経由）は維持する。 */
export { isRecord };

/** ODRL 制約として最低限の形（leftOperand / operator / rightOperand）を満たすか判定する。 */
function isConstraint(value: unknown): value is OdrlConstraint {
  if (!isRecord(value)) {
    return false;
  }
  const leftOperand = ownProperty<unknown>(value, 'leftOperand');
  const operator = ownProperty<unknown>(value, 'operator');
  const rightOperand = ownProperty<unknown>(value, 'rightOperand');
  return (
    typeof leftOperand === 'string' &&
    typeof operator === 'string' &&
    (typeof rightOperand === 'string' || Array.isArray(rightOperand))
  );
}

/** ルールの `severity` を読み取り、`deny` / `warn` 以外・未指定は既定値へ倒す。 */
export function coerceSeverity(rule: OdrlRule, fallback: 'deny' | 'warn'): 'deny' | 'warn' {
  const severity = ownProperty<unknown>(rule, 'severity');
  return severity === 'deny' || severity === 'warn' ? severity : fallback;
}

/** ルールの `action`（string | string[]）を配列へ正規化する。 */
function normalizeActions(action: OdrlRule['action']): string[] {
  if (typeof action === 'string') {
    return [action];
  }
  if (Array.isArray(action)) {
    return action.filter((a): a is string => typeof a === 'string');
  }
  return [];
}

/** 制約 1 件の評価結果。 */
interface ConstraintEvaluation {
  /** 制約を満たしたか（fail-open 既定での従来の boolean と同じ意味）。 */
  readonly satisfied: boolean;
  /** 評価器が解釈できなかったか（未知 `leftOperand` / 対応外 `operator` / 構造不正）。 */
  readonly undecidable: boolean;
}

/** 解釈できた制約の評価結果を組み立てる。 */
function decided(satisfied: boolean): ConstraintEvaluation {
  return { satisfied, undecidable: false };
}

/**
 * 単一の ODRL 制約を利用文脈に対して評価する。
 *
 * 対応 leftOperand: `purpose`（用途）/ `dateTime`（時刻、ISO 比較）/ `spatial`（地域、ISO 3166）。
 * 対応 operator は `OdrlOperator`（types.ts）を参照。
 *
 * 評価できない制約は `undecidable: true` を立てて返す:
 * - 未知の `leftOperand`: `satisfied: true`（「制約を課さない」= 従来の fail-open 既定）
 * - 対応外の `operator`: `satisfied: false`（制約不成立）
 *
 * `undecidable` をどう扱うかは呼び出し側の `UnknownVocabularyPolicy` に委ねる。
 *
 * 不正な ISO を含む `dateTime` 制約は例外にせず評価不能として扱う（`compareDateTime` 参照）。
 */
function evaluateConstraint(constraint: OdrlConstraint, ctx: UsageContext): ConstraintEvaluation {
  const leftOperand = ownProperty<OdrlConstraint['leftOperand']>(constraint, 'leftOperand');
  const operator = ownProperty<OdrlConstraint['operator']>(constraint, 'operator');
  const rightOperand = ownProperty<OdrlConstraint['rightOperand']>(constraint, 'rightOperand');
  if (leftOperand === undefined || operator === undefined || rightOperand === undefined) {
    // `isConstraint` を通った呼び出しでは起きないが、own 限定で読んだ値を検証せず使わない。
    // 3 項目のいずれかを自身のプロパティとして持たない constraint は構造不正なので、
    // `evaluateRule` の `!isConstraint(c)` と同じく「不成立かつ評価不能」に倒す（未知
    // `leftOperand` の fail-open とは別物: 語彙が未知なのではなく制約の形を成していない）。
    return { satisfied: false, undecidable: true };
  }
  switch (leftOperand) {
    case 'purpose':
    case 'spatial': {
      const left =
        leftOperand === 'purpose'
          ? ownProperty<string>(ctx, 'purpose')
          : ownProperty<string>(ctx, 'geolocation');
      const result = compareString(left, operator, rightOperand);
      return result === undefined ? { satisfied: false, undecidable: true } : decided(result);
    }
    case 'dateTime': {
      const nowIso = ownProperty<string>(ctx, 'at') ?? new Date().toISOString();
      const result = compareDateTime(nowIso, operator, rightOperand);
      return result === undefined ? { satisfied: false, undecidable: true } : decided(result);
    }
    default:
      // 未知の leftOperand。fail-open 既定では「制約を課さない」として通す。
      return { satisfied: true, undecidable: true };
  }
}

/** ルール 1 件の評価結果。 */
export interface RuleEvaluation {
  /** 全 constraint が合致したか（AND）。constraint 無しは常に合致。 */
  readonly matched: boolean;
  /** 評価できない制約を含んでいたか。`fail-open` 評価時は常に false。 */
  readonly undecidable: boolean;
}

/**
 * `constraint` を配列へ正規化する（単数指定を受け付ける）。
 *
 * ODRL / JSON-LD では要素が 1 件の集合を配列ではなく単一オブジェクトで書けるため、VC 本文には
 * `constraint: { leftOperand, operator, rightOperand }` の形が現れ得る。これを「配列でない＝制約なし」
 * と扱うと、`unknownConstraint: 'fail-closed'` を指定していてもルールが無条件に成立し、permission が
 * 常時許可になる（fail-open）。同ファイルの `action` は `normalizeActions`、`termsOfUse` 自体は
 * `collectEntries` が単数 / 配列を正規化しており、`constraint` だけが非対称だった。
 *
 * 配列でもオブジェクトでもない値（文字列・数値等）は構造不正なので、`isConstraint` の判定に委ねて
 * 「不成立かつ評価不能」に倒すため 1 要素の配列として返す。
 */
function normalizeConstraints(value: OdrlRule['constraint']): readonly unknown[] {
  if (Array.isArray(value)) {
    return value;
  }
  // `undefined` / `null` は「制約なし」。ここを 1 要素の配列にすると構造不正扱いになり、
  // 制約を持たない prohibition が発火しなくなる（従来挙動からの後退）。
  if (value === undefined || value === null) {
    return [];
  }
  return [value];
}

/**
 * ルールの全 constraint を評価する（AND）。constraint 無しは常に合致。
 *
 * `policy` が `fail-open`（既定）のときは、1 件でも不成立と分かった時点で打ち切る（未評価の制約に
 * 踏み込まないという従来の短絡評価をそのまま保つ）。`fail-closed` のときは評価できない制約を
 * 検出するため全件を評価する。
 *
 * @throws `UsageContext.at` が不正な ISO の場合（`VC_SCHEMA_INVALID` 3002）。VC 本文由来の
 *         `rightOperand` の不正は例外にせず評価不能として扱う（`compareDateTime` 参照）。
 */
export function evaluateRule(
  rule: OdrlRule,
  ctx: UsageContext,
  policy: UnknownVocabularyPolicy = 'fail-open',
): RuleEvaluation {
  const constraints = normalizeConstraints(ownProperty<OdrlRule['constraint']>(rule, 'constraint'));
  if (constraints.length === 0) {
    return { matched: true, undecidable: false };
  }
  let matched = true;
  let undecidable = false;
  for (const c of constraints) {
    if (!isConstraint(c)) {
      // 構造不正の constraint は合致とみなさない（評価不能でもある）。
      matched = false;
      undecidable = true;
    } else {
      const evaluation = evaluateConstraint(c, ctx);
      matched = matched && evaluation.satisfied;
      undecidable = undecidable || evaluation.undecidable;
    }
    if (!matched && policy === 'fail-open') {
      return { matched: false, undecidable: false };
    }
  }
  // fail-open では評価不能を判定に反映しないため、常に false を返す（呼び出し側の分岐を減らす）。
  return { matched, undecidable: policy === 'fail-closed' && undecidable };
}

/** ルールの `action` が本 SDK の評価対象かどうか。 */
export type ActionScope = 'in-scope' | 'out-of-scope';

/**
 * ルールが提示 / 利用文脈のアクションに適用対象かを判定する（action 無しは全アクション対象）。
 *
 * 本 SDK は VP 提示時の利用条件評価のみを扱うため、`use` / `present` / `*` を対象アクションとする。
 * `share` / `archive` / `invoke` 等の提示外アクション専用ルールは `out-of-scope` を返す。
 * `out-of-scope` のルールを無視する（fail-open）か `deny` に倒す（fail-closed）かは呼び出し側が決める。
 */
export function ruleActionScope(rule: OdrlRule): ActionScope {
  const actions = normalizeActions(ownProperty<OdrlRule['action']>(rule, 'action'));
  if (actions.length === 0) {
    return 'in-scope';
  }
  const inScope = actions.includes('use') || actions.includes('present') || actions.includes('*');
  return inScope ? 'in-scope' : 'out-of-scope';
}

/** 文字列として表示できないオペランドの代替表記。VC 本文の中身は載せない。 */
const UNREPRESENTABLE_OPERAND = '<invalid value>';

/**
 * 単一のオペランドを表示用文字列にする。
 *
 * 暗黙の `ToPrimitive` が `TypeError: No default value` になるのは、パース境界で `null`
 * プロトタイプ化された**オブジェクト**（`toString` / `valueOf` を持たない）と関数だけなので、
 * その 2 つに限って代替表記へ倒す。数値・真偽値・`null` は `String()` で安全に表示できるため
 * 潰さない（ODRL の `rightOperand` は回数・`elapsedTime` 等で実際に数値を取る）。
 */
function describeOperand(value: unknown): string {
  if (value !== null && typeof value === 'object') {
    return UNREPRESENTABLE_OPERAND;
  }
  if (typeof value === 'function') {
    return UNREPRESENTABLE_OPERAND;
  }
  return String(value);
}

/** `rightOperand` を表示用文字列にする。配列は要素ごとに表記へ倒して連結する。 */
function describeRightOperand(value: unknown): string {
  if (typeof value === 'string') {
    return value;
  }
  if (Array.isArray(value)) {
    return value.map((v) => describeOperand(v)).join(', ');
  }
  return describeOperand(value);
}

/**
 * ルールから制約を抽出して制限リストに反映する。
 *
 * `OdrlConstraint` は `operator: string` / `rightOperand: string | string[]` と宣言しているが、
 * 実体は VC 本文そのままなので型は嘘をつき得る。暗黙の文字列化（`String()` / `join`）に頼ると、
 * パース境界で `null` プロトタイプ化された値の `ToPrimitive` が `TypeError: No default value` に
 * なり、`checkTermsOfUse` が生の例外を漏らす。
 *
 * ここで `isConstraint` を満たさない制約を丸ごと読み飛ばすと、**制限が UI から黙って消える**
 * （fail-open）。そのため `leftOperand`（＝制限の種類 `kind`）が妥当なら制限自体は残し、表記だけ
 * 代替表現へ倒す。評価（合致判定）側は従来どおり `evaluateRule` が `isConstraint` で弾く。
 */
export function extractRestrictions(rule: OdrlRule, kindPrefix: string): ToURestriction[] {
  const out: ToURestriction[] = [];
  for (const c of normalizeConstraints(ownProperty<OdrlRule['constraint']>(rule, 'constraint'))) {
    if (!isRecord(c)) {
      continue;
    }
    const leftOperand = ownProperty<unknown>(c, 'leftOperand');
    if (typeof leftOperand !== 'string') {
      continue;
    }
    const operator = describeOperand(ownProperty<unknown>(c, 'operator'));
    const rightStr = describeRightOperand(ownProperty<unknown>(c, 'rightOperand'));
    out.push({
      kind: leftOperand,
      description: `${kindPrefix}: ${leftOperand} ${operator} ${rightStr}`,
    });
  }
  return out;
}

/**
 * 生成 ID の接頭辞に使う termsOfUse エントリ ID を決定する。
 *
 * `entryId` の型宣言は `string | undefined` だが、実体は VC 本文由来（`termsOfUse[].id`）で
 * `isRecord` フィルタしか通っておらず任意の値を取り得る。パース境界で `null` プロトタイプ化された
 * オブジェクトをテンプレートリテラルへ渡すと `TypeError: No default value` になり `checkTermsOfUse`
 * が落ちるため、文字列以外は例外にせず既定表記へ倒す。
 */
export function entryIdPrefix(entryId: string | undefined): string {
  return typeof entryId === 'string' ? entryId : 'tou';
}

/** ルール ID を決定する（uid → 生成 ID）。 */
export function ruleId(
  rule: OdrlRule,
  entryId: string | undefined,
  index: number,
  kind: string,
): string {
  const uid = ownProperty<OdrlRule['uid']>(rule, 'uid');
  return uid ?? `${entryIdPrefix(entryId)}#${kind}[${index}]`;
}
