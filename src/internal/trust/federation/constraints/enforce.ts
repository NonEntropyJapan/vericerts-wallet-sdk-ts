/**
 * Subordinate Statement の `constraints` の強制（OpenID Federation 1.0 §6.2）。
 *
 * 各 Subordinate Statement の `constraints` は独立に適用し、1 つでも破れば Trust Chain は不成立。
 * 制約を課すのは Statement の発行者（上位）、対象はその Statement の `sub` から Trust Chain の主体
 * （Leaf）までの下位エンティティ全体である。
 */

import { ErrorCodes, VericertsError } from '../../../errors.js';
import { ownProperty } from '../../../prototype-safety/own-property.js';
import type { EntityStatement, TrustChainNode } from '../federation-types.js';
import { consumeConstraintBudget, type StatementBudget } from '../statement/statement-budget.js';
import { hostOfEntityId, type NamingConstraints, type StatementConstraints } from './parse.js';

/** §5.1.1: 常に許可され、`allowed_entity_types` に含めてはならない Entity Type。 */
const FEDERATION_ENTITY = 'federation_entity';

/** ホスト `host` が名前制約 `name`（`.suffix` はサブドメインのみ・それ以外は当該ホスト）に合致するか。 */
function matchesName(host: string, name: string): boolean {
  return name.startsWith('.') ? host.endsWith(name) : host === name;
}

/** 名前制約の `permitted` / `excluded` を own に限って読む。 */
function ownNaming(naming: NamingConstraints) {
  return {
    permitted: ownProperty<readonly string[]>(naming, 'permitted'),
    excluded: ownProperty<readonly string[]>(naming, 'excluded'),
  };
}

/** 下位の Entity Identifier が名前空間制約を満たすか（解釈できない ID は満たさない）。 */
function satisfiesNaming(entityId: string, naming: NamingConstraints): boolean {
  const { permitted, excluded } = ownNaming(naming);
  const host = hostOfEntityId(entityId);
  if (host === undefined) {
    return false;
  }
  if (excluded?.some((name) => matchesName(host, name)) === true) {
    return false;
  }
  return permitted === undefined || permitted.some((name) => matchesName(host, name));
}

/** 強制に必要な、Statement 発行者から見た下位の情報。 */
export interface ConstraintSubjects {
  /** Statement の `sub` から Leaf までの Entity Identifier（`sub` が先頭、Leaf が末尾）。 */
  readonly entityIds: readonly string[];
  /** `sub` から Leaf までのエンティティについての Statement（ここまでに検証済みのノード）の `metadata` に現れる Entity Type。 */
  readonly entityTypes: readonly string[];
}

/**
 * 1 つの Subordinate Statement の `constraints` を強制する。
 *
 * - `max_path_length`: 発行者と Leaf の間に挟まる Intermediate 数（= `sub` から Leaf を除く下位の数）が
 *   上限以下であること。
 * - `naming_constraints`: `sub` から Leaf までの全 Entity Identifier のホスト部が、`excluded` に
 *   合致せず、`permitted` があればいずれかに合致すること。
 * - `allowed_entity_types`: 下位の `metadata` の Entity Type が許可リスト（と `federation_entity`）に含まれること。
 *   仕様は不許可 Type の `metadata` を取り除くが、本 SDK は解決後 metadata を返さず、呼び出し側が
 *   `TrustChainNode.statement.metadata` を直接読むため、取り除かずチェーンごと拒否する（fail-closed）。
 *
 * `allowed_entity_types` は 1 度だけ `Set` にして照合する（件数 N の Entity Type × 長さ M の許可リストの
 * 総当たり O(N×M) にしない）。走査・照合の総数は `budget` に計上し、超過は拒否する。
 *
 * @param constraints 検証済みの `constraints`（無ければ何もしない）。
 * @param subjects 制約の適用対象。
 * @param budget Trust Chain 構築 1 回の予算（省略時は単独検証として計上しない）。
 * @throws いずれかの制約を破る場合（TRUST_CHAIN_INVALID）。予算を超える場合も TRUST_CHAIN_INVALID
 *   （`context.reason` は `constraint_budget_exceeded`）。
 */
/**
 * 制約の 3 メンバを own に限って読む。省略された制約（`max_path_length` なし等）が `Object.prototype` の汚染値で
 * 課されたり、逆に課すはずの制約が外れたりしないようにする。
 */
function ownConstraints(constraints: StatementConstraints) {
  return {
    max_path_length: ownProperty<number>(constraints, 'max_path_length'),
    naming_constraints: ownProperty<NamingConstraints>(constraints, 'naming_constraints'),
    allowed_entity_types: ownProperty<readonly string[]>(constraints, 'allowed_entity_types'),
  };
}

export function enforceSubordinateConstraints(
  constraints: StatementConstraints | undefined,
  subjects: ConstraintSubjects,
  budget?: StatementBudget,
): void {
  if (constraints === undefined) {
    return;
  }
  const { max_path_length, naming_constraints, allowed_entity_types } = ownConstraints(constraints);
  consumeConstraintBudget(budget, constraintSteps(constraints, subjects));
  const intermediates = subjects.entityIds.length - 1;
  const violated =
    (max_path_length !== undefined && intermediates > max_path_length) ||
    (naming_constraints !== undefined &&
      !subjects.entityIds.every((id) => satisfiesNaming(id, naming_constraints))) ||
    (allowed_entity_types !== undefined &&
      !allTypesAllowed(subjects.entityTypes, allowed_entity_types));
  if (violated) {
    throw new VericertsError(ErrorCodes.TRUST_CHAIN_INVALID);
  }
}

/** すべての Entity Type が `federation_entity` か許可リストに含まれるか（許可リストは 1 度だけ Set 化）。 */
function allTypesAllowed(entityTypes: readonly string[], allowed: readonly string[]): boolean {
  const allowedSet = new Set(allowed);
  return entityTypes.every((type) => type === FEDERATION_ENTITY || allowedSet.has(type));
}

/** `enforceSubordinateConstraints` が行う走査・照合の総数（予算に計上する値）。 */
function constraintSteps(constraints: StatementConstraints, subjects: ConstraintSubjects): number {
  const { naming_constraints, allowed_entity_types } = ownConstraints(constraints);
  const { permitted, excluded } =
    naming_constraints === undefined ? {} : ownNaming(naming_constraints);
  const nameCount = (permitted?.length ?? 0) + (excluded?.length ?? 0);
  const typeSteps =
    allowed_entity_types === undefined
      ? 0
      : allowed_entity_types.length + subjects.entityTypes.length;
  return subjects.entityIds.length * nameCount + typeSteps;
}

/**
 * 新しく検証した Subordinate Statement の `constraints` を、ここまでに組んだチェーンへ強制する。
 *
 * `nodes` には Leaf の Entity Configuration と、下位から順に検証済みの Subordinate Statement（今回の
 * `subordinate` を含む）が並ぶ。それらの `sub` が「`subordinate.sub` から Leaf まで」の下位エンティティ全体に
 * なる。Entity Type は、`nodes` の Statement に加えて `below`（`subordinate.sub` から Leaf までの**全エンティティ**の
 * Entity Configuration）の `metadata` からも集める。中間エンティティの Entity Configuration は `nodes` に
 * 積まれない（Trust Anchor のものだけ最後に積む）ため、`below` を別に受けないと発行者の直下より 2 段以上
 * 下の中間エンティティの `metadata` が検査されない。同じ Statement を 2 度数えないよう
 * Entity Type は重複を除いて集める。
 *
 * @param subordinate 今回検証した Subordinate Statement（`constraints` を発行者として課す）。
 * @param nodes ここまでのノード列（`subordinate` を末尾に含む）。
 * @param below `subordinate.sub` から Leaf までの全エンティティの検証済み Entity Configuration のクレーム
 *   （`subordinate.sub` 自身・各中間・Leaf。`nodes` と重複してよい）。
 * @param budget Trust Chain 構築 1 回の予算（`enforceSubordinateConstraints` が走査・照合数を計上する）。
 * @throws 制約違反・予算超過（TRUST_CHAIN_INVALID）。
 */
export function enforceChainConstraints(
  subordinate: EntityStatement,
  nodes: readonly TrustChainNode[],
  below: readonly EntityStatement[],
  budget?: StatementBudget,
): void {
  const constraints = ownProperty<StatementConstraints>(subordinate, 'constraints');
  if (constraints === undefined) {
    return;
  }
  // `allowed_entity_types` が無ければ Entity Type は使わないので集めない。
  const entityTypes =
    ownConstraints(constraints).allowed_entity_types === undefined
      ? []
      : [
          ...new Set(
            [...nodes.map((node) => node.statement), ...below].flatMap((statement) =>
              Object.keys(ownProperty<object>(statement, 'metadata') ?? {}),
            ),
          ),
        ];
  enforceSubordinateConstraints(
    constraints,
    { entityIds: [...new Set(nodes.map((node) => node.sub))], entityTypes },
    budget,
  );
}
