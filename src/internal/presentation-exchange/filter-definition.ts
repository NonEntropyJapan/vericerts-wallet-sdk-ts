/**
 * PEx `field.filter`（JSON Schema 風フィルタ）の型とパース。
 *
 * `definition.ts` から分離（ファイルサイズ上限対応）。評価は `filter.ts`。
 */

import { rejectOversized } from '../auth/dcql/limits.js';
import { isPlainObject } from '../credential/object-guards.js';
import { ErrorCodes, VericertsError } from '../errors.js';
import { MAX_PATTERN_LENGTH } from '../primitives/safe-regex/index.js';
import { isNonEmptyString } from '../prototype-safety/non-empty-string.js';
import { ownProperty } from '../prototype-safety/own-property.js';
import { MAX_FILTER_ENUM_LENGTH } from './limits.js';

/** Field の JSON Schema 風フィルタ。 */
export interface JSONSchemaFilter {
  /** 期待する JSON 型（`string` / `number` / `boolean` / `object` / `array` / `null`）。 */
  readonly type: string;
  /** `type: 'string'` のときに値が満たすべき正規表現。 */
  readonly pattern?: string;
  /** JSON Schema と同じ深い等価で一致すべき値。 */
  readonly const?: unknown;
  /** いずれかに深い等価で一致すべき値の集合。 */
  readonly enum?: readonly unknown[];
  /** 数値の下限（以上）。値が数値のときだけ評価する。 */
  readonly minimum?: number;
  /** 数値の上限（以下）。値が数値のときだけ評価する。 */
  readonly maximum?: number;
  /** 数値の下限（より大きい。Draft 6+ の数値形式）。 */
  readonly exclusiveMinimum?: number;
  /** 数値の上限（より小さい。Draft 6+ の数値形式）。 */
  readonly exclusiveMaximum?: number;
  /** 文字列の最小長（Unicode コードポイント数）。値が文字列のときだけ評価する。 */
  readonly minLength?: number;
  /** 文字列の最大長（Unicode コードポイント数）。値が文字列のときだけ評価する。 */
  readonly maxLength?: number;
  /**
   * SDK が評価できないキーワード（`format` / `not` / `items` 等）を持っていた。
   * 黙って捨てると制約違反の VC がマッチする（fail-open）ため、評価時は不一致にする。
   */
  readonly unsatisfiable?: true;
}
/** 数値として評価するキーワード。値は有限な number でなければ 8030。 */
const NUMERIC_FILTER_KEYWORDS = [
  'minimum',
  'maximum',
  'exclusiveMinimum',
  'exclusiveMaximum',
  'minLength',
  'maxLength',
] as const;

/** 評価には使わないが、制約ではないので存在しても不一致にしないキーワード（注釈）。 */
const ANNOTATION_FILTER_KEYWORDS: ReadonlySet<string> = new Set([
  '$comment',
  '$id',
  '$schema',
  'default',
  'description',
  'examples',
  'readOnly',
  'title',
  'writeOnly',
]);

const SUPPORTED_FILTER_KEYWORDS: ReadonlySet<string> = new Set([
  'type',
  'pattern',
  'const',
  'enum',
  ...NUMERIC_FILTER_KEYWORDS,
  ...ANNOTATION_FILTER_KEYWORDS,
]);

/** `filter` をパース・検証する（`type` 必須。`pattern` は文字列、`enum` は配列、数値系は有限数）。 */
export function parseFilter(raw: unknown): JSONSchemaFilter {
  if (!isPlainObject(raw)) {
    throw new VericertsError(ErrorCodes.OID4VP_REQUEST_PARSE_FAILED);
  }
  const type = ownProperty<unknown>(raw, 'type');
  if (!isNonEmptyString(type)) {
    throw new VericertsError(ErrorCodes.OID4VP_REQUEST_PARSE_FAILED);
  }
  const pattern = ownProperty<unknown>(raw, 'pattern');
  if (pattern !== undefined && typeof pattern !== 'string') {
    throw new VericertsError(ErrorCodes.OID4VP_REQUEST_PARSE_FAILED);
  }
  if (pattern !== undefined && pattern.length > MAX_PATTERN_LENGTH) {
    // 長さだけは構造として拒否する（構文不正・非対応構文は評価時に fail-closed の不一致）。
    throw new VericertsError(ErrorCodes.OID4VP_REQUEST_PARSE_FAILED, {
      context: { reason: 'pattern_too_long' },
    });
  }
  const enumValues = ownProperty<unknown>(raw, 'enum');
  if (enumValues !== undefined && !Array.isArray(enumValues)) {
    throw new VericertsError(ErrorCodes.OID4VP_REQUEST_PARSE_FAILED);
  }
  rejectOversized(enumValues, MAX_FILTER_ENUM_LENGTH, 'filter_enum_too_large');
  // `const` は「指定なし」と「`undefined` を指定」を区別できないため、own 判定で分岐する。
  const hasConst = Object.hasOwn(raw, 'const');
  const numeric: Partial<Record<(typeof NUMERIC_FILTER_KEYWORDS)[number], number>> = {};
  for (const keyword of NUMERIC_FILTER_KEYWORDS) {
    const bound = ownProperty<unknown>(raw, keyword);
    if (bound === undefined) {
      continue;
    }
    if (typeof bound !== 'number' || !Number.isFinite(bound)) {
      throw new VericertsError(ErrorCodes.OID4VP_REQUEST_PARSE_FAILED);
    }
    numeric[keyword] = bound;
  }
  // 評価できないキーワードは捨てずに「満たせない filter」として保持する。
  const unsupported = Object.keys(raw).some((key) => !SUPPORTED_FILTER_KEYWORDS.has(key));
  return {
    type,
    ...(pattern !== undefined ? { pattern } : {}),
    ...(hasConst ? { const: ownProperty<unknown>(raw, 'const') } : {}),
    ...(enumValues !== undefined ? { enum: enumValues as readonly unknown[] } : {}),
    ...numeric,
    ...(unsupported ? { unsatisfiable: true as const } : {}),
  };
}
