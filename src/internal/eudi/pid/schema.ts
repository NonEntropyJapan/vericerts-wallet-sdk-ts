/**
 * ARF PID Rulebook に沿ったスキーマ検証。
 *
 * ARF PID Rulebook の必須 7 属性と、任意属性の型を検査する。
 * 検証内容:
 * - 必須属性 7 種の存在（欠落は 10002 `PID_REQUIRED_ATTR_MISSING`）
 * - 各属性の型・形式（不正は 10001 `PID_SCHEMA_INVALID`）
 *   - date 属性（`birth_date` / `issuance_date` / `expiry_date`）は ISO 8601 (`YYYY-MM-DD`)
 *   - `issuing_country` / `nationality` は ISO 3166-1 alpha-2（大文字 2 文字）
 *   - `age_over_NN` は boolean、`age_in_years` / `age_birth_year` は非負整数
 *
 * `validatePIDSchema` は例外を投げず `SchemaValidationResult` を返す。
 * 呼び出し側（`receivePID` 等）が `valid=false` を検知して適切な `VericertsError` を投げる。
 * 各違反の `required` は「PID Rulebook の必須属性に対する違反か」を表す。`vct` 不一致と
 * 必須属性の欠落は常に `required: true`、それ以外は属性名が {@link PID_MANDATORY_ATTRIBUTES}
 * に含まれるかで決まる（FO-4）。
 *
 * セキュリティ上の注意:
 * - `SchemaError.message` に属性値（PII）を含めない。path は属性名のみ。
 */

import { isNonEmptyString } from '../../prototype-safety/non-empty-string.js';
import { ownProperty } from '../../prototype-safety/own-property.js';
import {
  PID_MANDATORY_ATTRIBUTES,
  PID_VCT,
  type PIDClaims,
  type PIDCredential,
  type SchemaError,
  type SchemaValidationResult,
} from './types.js';

/** ISO 8601 の完全日付（`YYYY-MM-DD`）。時刻は PID の date 属性では扱わない。 */
const ISO_DATE_RE = /^\d{4}-\d{2}-\d{2}$/;
/** ISO 3166-1 alpha-2（大文字 2 文字）。 */
const ISO_COUNTRY_RE = /^[A-Z]{2}$/;
/** `age_over_NN` 属性名（NN は 1 桁以上の整数）。 */
const AGE_OVER_RE = /^age_over_\d+$/;

/** `YYYY-MM-DD` として妥当な暦日か（月・日の範囲と実在日を検査）。 */
function isValidCalendarDate(value: string): boolean {
  if (!ISO_DATE_RE.test(value)) {
    return false;
  }
  const year = Number(value.slice(0, 4));
  const month = Number(value.slice(5, 7));
  const day = Number(value.slice(8, 10));
  if (month < 1 || month > 12 || day < 1 || day > 31) {
    return false;
  }
  const date = new Date(Date.UTC(year, month - 1, day));
  return (
    date.getUTCFullYear() === year && date.getUTCMonth() === month - 1 && date.getUTCDate() === day
  );
}

/** 非負整数か（`age_in_years` / `age_birth_year` 用）。 */
function isNonNegativeInteger(value: unknown): boolean {
  return typeof value === 'number' && Number.isInteger(value) && value >= 0;
}

const DATE_ATTRIBUTES = ['birth_date', 'issuance_date', 'expiry_date'] as const;

/** 必須属性名の索引（違反 1 件ごとの `required` 判定用）。 */
const MANDATORY_ATTRIBUTE_SET: ReadonlySet<string> = new Set(PID_MANDATORY_ATTRIBUTES);

/**
 * 単一属性の型・形式を検査し、違反があれば `SchemaError` を返す（なければ null）。
 *
 * `required` は「その属性が PID Rulebook の必須属性か」を呼び出し側から受け取る。
 * 利用側が任意属性のみの違反を識別できるよう、各違反に必須・任意の別を記録する。
 */
function validateAttribute(name: string, value: unknown, required: boolean): SchemaError | null {
  // 必須文字列属性（date / country は個別検査）。
  if (name === 'family_name' || name === 'given_name' || name === 'issuing_authority') {
    return isNonEmptyString(value)
      ? null
      : { path: name, message: '空でない文字列である必要があります', required };
  }
  if ((DATE_ATTRIBUTES as readonly string[]).includes(name)) {
    return typeof value === 'string' && isValidCalendarDate(value)
      ? null
      : {
          path: name,
          message: 'ISO 8601 (YYYY-MM-DD) 形式の妥当な日付である必要があります',
          required,
        };
  }
  if (name === 'issuing_country' || name === 'nationality') {
    return typeof value === 'string' && ISO_COUNTRY_RE.test(value)
      ? null
      : {
          path: name,
          message: 'ISO 3166-1 alpha-2（大文字 2 文字）である必要があります',
          required,
        };
  }
  if (AGE_OVER_RE.test(name)) {
    return typeof value === 'boolean'
      ? null
      : { path: name, message: 'boolean である必要があります', required };
  }
  if (name === 'age_in_years' || name === 'age_birth_year') {
    return isNonNegativeInteger(value)
      ? null
      : { path: name, message: '非負整数である必要があります', required };
  }
  if (name === 'gender') {
    // ISO/IEC 5218（0-9 のコード）。非負整数として扱う。
    return isNonNegativeInteger(value)
      ? null
      : { path: name, message: 'ISO/IEC 5218 の非負整数コードである必要があります', required };
  }
  // その他の任意属性（resident_* / document_number 等）は存在時に非空文字列を要求する。
  // 型が明示されていない属性は緩く許容し、欠落は必須検査でのみ扱う。
  return null;
}

/**
 * PID クレーム集合を ARF PID Rulebook に照らして検証する。
 *
 * `validatePIDSchema` の内部実装。必須属性の欠落と各属性の型・形式を検査し、
 * すべての違反を `errors` に集約して返す（最初の違反で打ち切らない）。
 */
export function validatePIDClaims(claims: PIDClaims): SchemaValidationResult {
  const errors: SchemaError[] = [];

  // 必須属性の存在検査（欠落 = 10002 相当）。**自身のプロパティに限って読む**。
  // `claims[attr]` の鎖読みだと `Object.prototype.family_name` 等の
  // 汚染値を拾い、**必須属性を欠く PID が「存在する」と判定されて検証を通る**（fail-open）。
  for (const attr of PID_MANDATORY_ATTRIBUTES) {
    const value = ownProperty<unknown>(claims, attr);
    if (value === undefined || value === null) {
      errors.push({ path: attr, message: '必須属性が欠落しています', required: true });
    }
  }

  // 存在する属性の型・形式検査（不正 = 10001 相当）。
  for (const [name, value] of Object.entries(claims)) {
    if (value === undefined || value === null) {
      continue;
    }
    const error = validateAttribute(name, value, MANDATORY_ATTRIBUTE_SET.has(name));
    if (error !== null) {
      errors.push(error);
    }
  }

  return errors.length === 0 ? { valid: true } : { valid: false, errors };
}

/**
 * PID Credential を ARF PID Rulebook に照らして検証する。
 *
 * `vct` が `urn:eudi:pid:1` であることと、`claims` の Rulebook 準拠を検査する。
 * 例外は投げず `SchemaValidationResult` を返す。
 */
export function validatePIDSchema(pid: PIDCredential): SchemaValidationResult {
  // `claims` / `vct` も**自身のプロパティに限って読む**。
  // `pid.claims` / `pid.vct` の鎖読みは 2 通りの fail-open を作る。
  // - `vct`: own に `vct` を持たない PID が `Object.prototype.vct = 'urn:eudi:pid:1'` の汚染下で
  //   型識別子の照合を素通りし、**PID ではない SD-JWT VC が `{ valid: true }` になる**。
  // - `claims`: own に `claims` を持たない PID が `Object.prototype.claims` の汚染値を拾い、
  //   **攻撃者のクレーム集合が Rulebook 検証を通って valid と報告される**。
  // `PIDCredential` は呼び出し側が組み立てて渡す入力なので、パース境界では
  // 守られない。ここでの own 限定読みが唯一の防御線である。
  const claims = ownProperty<PIDClaims>(pid, 'claims');
  const vct = ownProperty<string>(pid, 'vct');
  const result = validatePIDClaims(claims ?? ({} as PIDClaims));
  if (vct !== PID_VCT) {
    const vctError: SchemaError = {
      path: 'vct',
      message: `vct は ${PID_VCT} である必要があります`,
      required: true,
    };
    // `result.errors` も **own 限定**で読む。成功時の `result` は `{ valid: true }` リテラルで
    // own `errors` を持たないため、鎖読みだと `Object.prototype.errors` の汚染値が返り値へ
    // 混入する（攻撃者が選んだ `SchemaError` が「検証結果」として返る）。非 iterable な汚染値
    // ならスプレッドが**生の `TypeError`** を投げ、「例外は投げず結果を返す」契約
    // を破る。
    const existing = Object.hasOwn(result, 'errors') ? result.errors : undefined;
    return {
      valid: false,
      errors: [vctError, ...(existing ?? [])],
    };
  }
  return result;
}
