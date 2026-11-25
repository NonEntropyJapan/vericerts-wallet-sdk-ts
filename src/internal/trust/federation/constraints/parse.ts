/**
 * Entity Statement の `constraints` / `crit` / `metadata_policy_crit` の構造検証。
 *
 * OpenID Federation 1.0 §3.1（`crit` / `metadata_policy_crit`）と §6.2（Constraints）を扱う。
 *
 * - `crit` / `metadata_policy_crit`: 「列挙されたクレーム / ポリシー演算子を理解できなければ Statement を
 *   拒否する」宣言。本 SDK は仕様定義外の拡張クレームも拡張ポリシー演算子も実装しない（`crit` は仕様定義
 *   クレームを含めてはならない・`metadata_policy_crit` も標準演算子を含めてはならないため、列挙された時点で
 *   すべて「理解できない」）ので、**存在した時点で拒否**する（fail-closed）。
 * - `constraints`: 本 SDK が理解する 3 種（`max_path_length` / `naming_constraints` /
 *   `allowed_entity_types`）は不正な形を拒否し、強制は `enforce.ts` が行う。未知のメンバは仕様
 *   どおり無視する。
 */

import { ErrorCodes, VericertsError } from '../../../errors.js';
import { isNonEmptyString } from '../../../prototype-safety/non-empty-string.js';

/** `constraints.naming_constraints`（RFC 5280 §4.2.1.10 の名前制約に倣う URI ホスト部の部分木）。 */
export interface NamingConstraints {
  /** 許可するホスト部（`.example.com` はサブドメインのみ、`host.example.com` は当該ホストのみ）。 */
  readonly permitted?: readonly string[];
  /** 除外するホスト部（`permitted` に含まれていても除外が優先する）。 */
  readonly excluded?: readonly string[];
}

/** Subordinate Statement の `constraints`（本 SDK が理解し強制するメンバのみ）。 */
export interface StatementConstraints {
  /** 制約を課すエンティティから Trust Chain の主体までに挟まってよい Intermediate の最大数。 */
  readonly max_path_length?: number;
  /** 下位の Entity Identifier に課す名前空間制約。 */
  readonly naming_constraints?: NamingConstraints;
  /** 下位が `metadata` に持ってよい Entity Type（`federation_entity` は常に許可）。 */
  readonly allowed_entity_types?: readonly string[];
}

/** 不正な制約の形はすべて `TRUST_CHAIN_INVALID`（fail-closed）。 */
function invalid(): never {
  throw new VericertsError(ErrorCodes.TRUST_CHAIN_INVALID);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** URL のホスト部を小文字・末尾ドット無しに正規化する。https 以外・不正な URL は `undefined`。 */
export function hostOfEntityId(entityId: string): string | undefined {
  try {
    const url = new URL(entityId);
    return url.protocol === 'https:' && url.hostname !== ''
      ? url.hostname.toLowerCase().replace(/\.$/, '')
      : undefined;
  } catch {
    return undefined;
  }
}

/** 名前制約 1 件を正規化する（先頭の `.` は保持）。ホスト以外を含む・解釈できない値は拒否。 */
function parseConstraintName(raw: unknown): string {
  if (!isNonEmptyString(raw) || /[\s/?#@:\\]/.test(raw)) {
    return invalid();
  }
  const dotted = raw.startsWith('.');
  const host = hostOfEntityId(`https://${dotted ? raw.slice(1) : raw}`);
  return host === undefined ? invalid() : `${dotted ? '.' : ''}${host}`;
}

function parseNameList(value: unknown): readonly string[] {
  return Array.isArray(value) ? value.map(parseConstraintName) : invalid();
}

function parseNamingConstraints(value: unknown): NamingConstraints {
  if (!isRecord(value)) {
    return invalid();
  }
  return {
    ...(value.permitted === undefined ? {} : { permitted: parseNameList(value.permitted) }),
    ...(value.excluded === undefined ? {} : { excluded: parseNameList(value.excluded) }),
  };
}

/**
 * `constraints` クレームを検証・正規化する。
 *
 * @param value payload の `constraints`（未検証）。
 * @returns 理解できるメンバだけを持つ制約。
 * @throws オブジェクトでない / `max_path_length` が非負整数でない / 名前制約・Entity Type が不正な場合
 *   （TRUST_CHAIN_INVALID）。
 */
export function parseConstraints(value: unknown): StatementConstraints {
  if (!isRecord(value)) {
    return invalid();
  }
  const { max_path_length: maxPathLength, allowed_entity_types: allowedTypes } = value;
  if (
    maxPathLength !== undefined &&
    !(
      typeof maxPathLength === 'number' &&
      Number.isSafeInteger(maxPathLength) &&
      maxPathLength >= 0
    )
  ) {
    return invalid();
  }
  if (
    allowedTypes !== undefined &&
    !(Array.isArray(allowedTypes) && allowedTypes.every((type) => isNonEmptyString(type)))
  ) {
    return invalid();
  }
  return {
    ...(maxPathLength === undefined ? {} : { max_path_length: maxPathLength }),
    ...(value.naming_constraints === undefined
      ? {}
      : { naming_constraints: parseNamingConstraints(value.naming_constraints) }),
    ...(allowedTypes === undefined
      ? {}
      : { allowed_entity_types: allowedTypes as readonly string[] }),
  };
}

/**
 * 理解できない拡張を「理解必須」と宣言する Statement を拒否する。
 *
 * @param payload デコード済み JWT payload。
 * @throws `crit` または `metadata_policy_crit` が存在する場合（TRUST_CHAIN_INVALID）。
 */
export function assertNoCriticalExtensions(payload: Record<string, unknown>): void {
  if (payload.crit !== undefined || payload.metadata_policy_crit !== undefined) {
    invalid();
  }
}
