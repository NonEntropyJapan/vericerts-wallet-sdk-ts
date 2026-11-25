/**
 * DIF Presentation Exchange v2 の Presentation Definition 型とパース・構造検証。
 *
 * 本モジュールは Verifier が送ってくる Presentation Definition（JSON object）を構造化する
 * **純粋関数** を提供する（ネットワーク・署名検証・暗号プリミティブは一切伴わない）。
 *
 * セキュリティ上の注意:
 * - 例外メッセージ・`context` にクレーム値や VC 本文を含めない。
 */

import { isPlainObject } from '../credential/object-guards.js';
import { ErrorCodes, VericertsError } from '../errors.js';
import { isNonEmptyString } from '../prototype-safety/non-empty-string.js';
import { ownProperty } from '../prototype-safety/own-property.js';
import { type JSONSchemaFilter, parseFilter } from './filter-definition.js';
import { rejectTooManyInputDescriptors } from './limits.js';

/**
 * Verifier 由来の `path` の上限。評価量そのものは評価時の走査量予算が抑えるが、
 * 巨大な path・候補・フィールドを構造として先に拒否し、評価前の処理量も絞る。
 */
const MAX_PATH_LENGTH = 512;
const MAX_PATHS_PER_FIELD = 8;
const MAX_FIELDS_PER_DESCRIPTOR = 64;

/** Input Descriptor の format 要件。 */
export interface FormatRequirement {
  /** JWT-VC（JSON）で受理する JWS alg。 */
  readonly jwt_vc_json?: { readonly alg: readonly string[] };
  /** SD-JWT VC（既定の `typ`）で受理する JWS alg。 */
  readonly 'dc+sd-jwt'?: { readonly alg: readonly string[] };
  /** SD-JWT VC（移行期間の後方互換 `typ`）で受理する JWS alg。 */
  readonly 'vc+sd-jwt'?: { readonly alg: readonly string[] };
  /** Linked Data Proof VC で受理する proof type。 */
  readonly ldp_vc?: { readonly proof_type: readonly string[] };
  /**
   * 元の要求が SDK 非対応の format（`mso_mdoc` / `jwt_vc` / `jwt_vp` 等）のキーしか持たなかった。
   * 満たせる VC は無いので評価時に候補から外す（`format: {}` = 制約なし と区別する）。
   */
  readonly unsatisfiable?: true;
}

/** Constraints の単一フィールド条件。 */
export interface Field {
  /** JSONPath 式の候補配列（例: `["$.credentialSubject.name"]`）。先頭から順に試す。 */
  readonly path: readonly string[];
  /** 解決した値に適用するフィルタ。 */
  readonly filter?: JSONSchemaFilter;
  /** `true` なら値が解決できなくても不一致にしない。 */
  readonly optional?: boolean;
}

/** Input Descriptor の制約。 */
export interface Constraints {
  /** 要求フィールド条件。 */
  readonly fields: readonly Field[];
  /** 選択的開示の要求度。評価ロジックには影響しない（提示時の方針として保持する）。 */
  readonly limit_disclosure?: 'required' | 'preferred';
}

/** 単一の入力記述子。 */
export interface InputDescriptor {
  /** Definition 内でのこの記述子の識別子（`DescriptorMap.id` から参照される）。 */
  readonly id: string;
  /** 表示名。 */
  readonly name?: string;
  /** 要求目的。 */
  readonly purpose?: string;
  /** 要求 format。省略時は format を問わない。 */
  readonly format?: FormatRequirement;
  /** 要求フィールド条件。 */
  readonly constraints: Constraints;
}

/** Presentation Definition。 */
export interface PresentationDefinition {
  /** Definition の識別子（`PresentationSubmission.definition_id` から参照される）。 */
  readonly id: string;
  /** 表示名。 */
  readonly name?: string;
  /** 要求目的。 */
  readonly purpose?: string;
  /** 入力記述子の配列（空不可）。 */
  readonly input_descriptors: readonly InputDescriptor[];
}

/** own 限定・1 回読みで任意の文字列メンバを読む。存在するが文字列でなければ 8030。 */
function parseOptionalString(raw: object, key: string): string | undefined {
  const value = ownProperty<unknown>(raw, key);
  if (value === undefined) {
    return undefined;
  }
  if (typeof value !== 'string') {
    throw new VericertsError(ErrorCodes.OID4VP_REQUEST_PARSE_FAILED);
  }
  return value;
}

/** 単一 `Field` をパース・検証する。`path` は非空の文字列配列（各要素も非空）が必須。 */
function parseField(raw: unknown): Field {
  if (!isPlainObject(raw)) {
    throw new VericertsError(ErrorCodes.OID4VP_REQUEST_PARSE_FAILED);
  }
  const path = ownProperty<unknown>(raw, 'path');
  if (!Array.isArray(path) || path.length === 0 || !path.every(isNonEmptyString)) {
    throw new VericertsError(ErrorCodes.OID4VP_REQUEST_PARSE_FAILED);
  }
  if (path.length > MAX_PATHS_PER_FIELD || path.some((p) => p.length > MAX_PATH_LENGTH)) {
    throw new VericertsError(ErrorCodes.OID4VP_REQUEST_PARSE_FAILED, {
      context: { reason: 'path_too_large' },
    });
  }
  const rawFilter = ownProperty<unknown>(raw, 'filter');
  const optional = ownProperty<unknown>(raw, 'optional');
  if (optional !== undefined && typeof optional !== 'boolean') {
    throw new VericertsError(ErrorCodes.OID4VP_REQUEST_PARSE_FAILED);
  }
  return {
    path: path as readonly string[],
    ...(rawFilter !== undefined ? { filter: parseFilter(rawFilter) } : {}),
    ...(optional !== undefined ? { optional } : {}),
  };
}

/** `constraints` をパース・検証する（`fields` 配列が必須。空配列は「条件なし」として許す）。 */
function parseConstraints(raw: unknown): Constraints {
  if (!isPlainObject(raw)) {
    throw new VericertsError(ErrorCodes.OID4VP_REQUEST_PARSE_FAILED);
  }
  const rawFields = ownProperty<unknown>(raw, 'fields');
  if (!Array.isArray(rawFields)) {
    throw new VericertsError(ErrorCodes.OID4VP_REQUEST_PARSE_FAILED);
  }
  if (rawFields.length > MAX_FIELDS_PER_DESCRIPTOR) {
    throw new VericertsError(ErrorCodes.OID4VP_REQUEST_PARSE_FAILED, {
      context: { reason: 'too_many_fields' },
    });
  }
  const limitDisclosure = parseOptionalString(raw, 'limit_disclosure');
  if (
    limitDisclosure !== undefined &&
    limitDisclosure !== 'required' &&
    limitDisclosure !== 'preferred'
  ) {
    throw new VericertsError(ErrorCodes.OID4VP_REQUEST_PARSE_FAILED);
  }
  return {
    fields: rawFields.map(parseField),
    ...(limitDisclosure !== undefined ? { limit_disclosure: limitDisclosure } : {}),
  };
}

/**
 * `format` をパース・検証する。既知キーの値は object であること。既知キーを 1 つも持たず非 SDK 対応の
 * キーだけを持つ要件は `unsatisfiable`（真に空の `{}` だけが「制約なし」）。
 */
function parseFormat(raw: unknown): FormatRequirement {
  if (!isPlainObject(raw)) {
    throw new VericertsError(ErrorCodes.OID4VP_REQUEST_PARSE_FAILED);
  }
  const format: Record<string, unknown> = {};
  for (const key of ['jwt_vc_json', 'dc+sd-jwt', 'vc+sd-jwt', 'ldp_vc']) {
    const entry = ownProperty<unknown>(raw, key);
    if (entry === undefined) {
      continue;
    }
    if (!isPlainObject(entry)) {
      throw new VericertsError(ErrorCodes.OID4VP_REQUEST_PARSE_FAILED);
    }
    format[key] = entry;
  }
  if (Object.keys(format).length === 0 && Object.keys(raw).length > 0) {
    format.unsatisfiable = true;
  }
  return format as FormatRequirement;
}

/** 単一 `InputDescriptor` をパース・検証する（`id` / `constraints` 必須）。 */
function parseInputDescriptor(raw: unknown): InputDescriptor {
  if (!isPlainObject(raw)) {
    throw new VericertsError(ErrorCodes.OID4VP_REQUEST_PARSE_FAILED);
  }
  const id = ownProperty<unknown>(raw, 'id');
  if (!isNonEmptyString(id)) {
    throw new VericertsError(ErrorCodes.OID4VP_REQUEST_PARSE_FAILED);
  }
  const name = parseOptionalString(raw, 'name');
  const purpose = parseOptionalString(raw, 'purpose');
  const rawFormat = ownProperty<unknown>(raw, 'format');
  const rawConstraints = ownProperty<unknown>(raw, 'constraints');
  if (rawConstraints === undefined) {
    throw new VericertsError(ErrorCodes.OID4VP_REQUEST_PARSE_FAILED);
  }
  return {
    id,
    ...(name !== undefined ? { name } : {}),
    ...(purpose !== undefined ? { purpose } : {}),
    ...(rawFormat !== undefined ? { format: parseFormat(rawFormat) } : {}),
    constraints: parseConstraints(rawConstraints),
  };
}

/**
 * Presentation Definition（JSON object）をパース・構造検証する。
 *
 * この関数自体が**公開 SDK API**（`src/exports/auth.ts` からエクスポート）であり、利用者が
 * 通常の `JSON.parse` の戻り値や手組みのオブジェクトリテラル（`Object.prototype` を継承）を
 * そのまま渡し得る。そのため `raw` およびネストした `input_descriptors[i]` /
 * `.constraints` / `.constraints.fields[j]` / `.format` の各メンバは own 限定・1 回読みで
 * 読む（`own-property.ts` の規約。`parseDcqlQuery` と同じ扱い）。鎖読みのままだと、例えば
 * `constraints` を持たない記述子でも `Object.prototype.constraints` の汚染値が「指定された」
 * ものとして扱われ、`8030` で拒否すべき不正な構造がパースを通過し得る。
 *
 * @param raw Presentation Definition の JSON object。
 * @returns 構造検証済み `PresentationDefinition`。
 * @throws `id` / `input_descriptors` 欠落・型不正・記述子 id 重複・記述子数が `MAX_INPUT_DESCRIPTORS` 超過時（VericertsError、code `8030`）。
 */
export function parsePresentationDefinition(raw: Record<string, unknown>): PresentationDefinition {
  const id = ownProperty<unknown>(raw, 'id');
  if (!isNonEmptyString(id)) {
    throw new VericertsError(ErrorCodes.OID4VP_REQUEST_PARSE_FAILED);
  }
  const name = parseOptionalString(raw, 'name');
  const purpose = parseOptionalString(raw, 'purpose');

  const rawDescriptors = ownProperty<unknown>(raw, 'input_descriptors');
  if (!Array.isArray(rawDescriptors) || rawDescriptors.length === 0) {
    throw new VericertsError(ErrorCodes.OID4VP_REQUEST_PARSE_FAILED);
  }
  // 記述子を 1 件もパースする前に件数だけで拒否する（`parseDcqlQuery` の `MAX_DCQL_CREDENTIALS` と同じ）。
  rejectTooManyInputDescriptors(rawDescriptors);
  const inputDescriptors = rawDescriptors.map(parseInputDescriptor);

  // 記述子 id の重複は曖昧なマッチ結果・Submission を生むため拒否する（`parseDcqlQuery` と同じ）。
  const ids = new Set<string>();
  for (const descriptor of inputDescriptors) {
    if (ids.has(descriptor.id)) {
      throw new VericertsError(ErrorCodes.OID4VP_REQUEST_PARSE_FAILED, {
        context: { reason: 'duplicate_input_descriptor_id' },
      });
    }
    ids.add(descriptor.id);
  }

  return {
    id,
    ...(name !== undefined ? { name } : {}),
    ...(purpose !== undefined ? { purpose } : {}),
    input_descriptors: inputDescriptors,
  };
}
