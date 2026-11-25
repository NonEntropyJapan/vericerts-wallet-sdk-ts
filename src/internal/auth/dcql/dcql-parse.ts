/**
 * DCQL（Digital Credentials Query Language）クエリのパース・構造検証。
 *
 * OpenID for Verifiable Presentations 1.0（Draft 24+）準拠。
 *
 * **評価（`dcql.ts`）と分けてある理由。** 「RP が送ってきた JSON を型のある構造体にする」ことと
 * 「その構造体を保持クレデンシャルに突き合わせる」ことは失敗の意味が違う（前者は `8030` で
 * 拒否、後者は「マッチしない」）。1 ファイル 300 行の上限に収めるための分割でもある。
 * 型定義は `dcql.ts` が持ち、本モジュールは**型としてのみ**参照する（実行時の import は
 * 一方向 — `dcql.ts` が本モジュールを読む — に保つ）。
 *
 * セキュリティ上の注意:
 * - 例外メッセージ・`context` にクレーム値や VC 本文を含めない。
 */

import { ErrorCodes, VericertsError } from '../../errors.js';
import { isNonEmptyString } from '../../prototype-safety/non-empty-string.js';
import { ownProperty } from '../../prototype-safety/own-property.js';
import type { DcqlClaim, DcqlCredential, DcqlMeta, DcqlQuery } from './dcql.js';
import {
  MAX_DCQL_ARRAY_LENGTH,
  MAX_DCQL_CLAIMS_PER_CREDENTIAL,
  MAX_DCQL_CREDENTIALS,
  MAX_DCQL_PATH_LENGTH,
  rejectOversized,
} from './limits.js';

/** `parseDcqlQuery` が 8030 に倒す理由（Wallet が評価できない DCQL 条件）。 */
const UNSUPPORTED_DCQL_MEMBER = { reason: 'unsupported_dcql_member' } as const;

/** クエリのトップレベルで Wallet が評価できない（黙って捨てると要求が緩む）メンバ。 */
const UNSUPPORTED_QUERY_MEMBERS = ['credential_sets'] as const;

/** 要件（`credentials[i]`）で Wallet が評価できないメンバ。 */
const UNSUPPORTED_CREDENTIAL_MEMBERS = ['claim_sets', 'trusted_authorities'] as const;

/** 評価対応済みの `meta` メンバ。これ以外（`doctype_values` 等）は制約として評価できない。 */
const SUPPORTED_META_MEMBERS: ReadonlySet<string> = new Set(['vct_values', 'type_values']);

/**
 * `multiple` を検証する。
 *
 * `multiple: false` は DCQL の既定値と同じで「1 件だけ返す」という意味しか持たず、要求を緩めない。
 * 受理して無視する。`true`（複数提示の要求）は評価できないので拒否する。boolean 以外も、意味を
 * 決められない以上は拒否する（fail-closed）。
 */
function rejectUnsupportedMultiple(raw: object): void {
  const multiple = ownProperty<unknown>(raw, 'multiple');
  if (multiple !== undefined && multiple !== false) {
    throw new VericertsError(ErrorCodes.OID4VP_REQUEST_PARSE_FAILED, {
      context: UNSUPPORTED_DCQL_MEMBER,
    });
  }
}

/** `type_values`（文字列配列の非空配列）か。内側の配列も非空で、要素はすべて文字列であること。 */
function isTypeValues(value: unknown): value is readonly (readonly string[])[] {
  return (
    Array.isArray(value) &&
    value.length > 0 &&
    value.every((inner) => isStringArray(inner) && inner.length > 0)
  );
}

/**
 * `meta` が評価未対応の制約メンバ（`type_values` / `doctype_value(s)` 等）を持つか。
 *
 * 黙って捨てると Verifier が絞り込んだつもりの要求に無関係な VC が通る（fail-open）ため、パースでは
 * 8030、評価（`dcql.ts`）では「マッチしない」に倒す。own の列挙可能キーだけを見る。
 */
export function hasUnsupportedMetaMember(meta: object): boolean {
  return Object.keys(meta).some((key) => !SUPPORTED_META_MEMBERS.has(key));
}

/** `raw` が評価未対応メンバのいずれかを own に持つなら 8030（`unsupported_dcql_member`）。 */
function rejectUnsupportedMembers(raw: object, members: readonly string[]): void {
  if (members.some((member) => Object.hasOwn(raw, member))) {
    throw new VericertsError(ErrorCodes.OID4VP_REQUEST_PARSE_FAILED, {
      context: UNSUPPORTED_DCQL_MEMBER,
    });
  }
}

/** 文字列配列か（空要素なし）。 */
function isStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((v) => typeof v === 'string');
}

/**
 * 単一 DCQL クレーム条件をパース・検証する。
 *
 * `path` / `values` は own 限定・1 回読みで読む（`parseDcqlQuery` の JSDoc 参照）。
 */
function parseClaim(raw: unknown): DcqlClaim {
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) {
    throw new VericertsError(ErrorCodes.OID4VP_REQUEST_PARSE_FAILED);
  }
  const path = ownProperty<unknown>(raw, 'path');
  rejectOversized(path, MAX_DCQL_PATH_LENGTH);
  if (!isStringArray(path) || path.length === 0) {
    throw new VericertsError(ErrorCodes.OID4VP_REQUEST_PARSE_FAILED);
  }
  const values = ownProperty<unknown>(raw, 'values');
  rejectOversized(values, MAX_DCQL_ARRAY_LENGTH);
  if (values !== undefined && !Array.isArray(values)) {
    throw new VericertsError(ErrorCodes.OID4VP_REQUEST_PARSE_FAILED);
  }
  const claim: DcqlClaim = {
    path,
    ...(values !== undefined ? { values: values as readonly unknown[] } : {}),
  };
  return claim;
}

/**
 * 単一 DCQL クレデンシャル要件をパース・検証する。
 *
 * `id` / `format` / `meta` / `meta.vct_values` / `claims` は own 限定・1 回読みで読む
 * （`parseDcqlQuery` の JSDoc 参照）。
 */
function parseCredential(raw: unknown): DcqlCredential {
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) {
    throw new VericertsError(ErrorCodes.OID4VP_REQUEST_PARSE_FAILED);
  }
  rejectUnsupportedMembers(raw, UNSUPPORTED_CREDENTIAL_MEMBERS);
  rejectUnsupportedMultiple(raw);
  const id = ownProperty<unknown>(raw, 'id');
  const format = ownProperty<unknown>(raw, 'format');
  if (!isNonEmptyString(id) || !isNonEmptyString(format)) {
    throw new VericertsError(ErrorCodes.OID4VP_REQUEST_PARSE_FAILED);
  }

  let meta: DcqlMeta | undefined;
  const rawMeta = ownProperty<unknown>(raw, 'meta');
  if (rawMeta !== undefined) {
    if (typeof rawMeta !== 'object' || rawMeta === null || Array.isArray(rawMeta)) {
      throw new VericertsError(ErrorCodes.OID4VP_REQUEST_PARSE_FAILED);
    }
    if (hasUnsupportedMetaMember(rawMeta)) {
      throw new VericertsError(ErrorCodes.OID4VP_REQUEST_PARSE_FAILED, {
        context: UNSUPPORTED_DCQL_MEMBER,
      });
    }
    const vctValues = ownProperty<unknown>(rawMeta, 'vct_values');
    // `vct_values` は非空配列必須（DCQL）。空配列は「制約なし」ではなく不正として拒否する。
    rejectOversized(vctValues, MAX_DCQL_ARRAY_LENGTH);
    if (vctValues !== undefined && (!isStringArray(vctValues) || vctValues.length === 0)) {
      throw new VericertsError(ErrorCodes.OID4VP_REQUEST_PARSE_FAILED);
    }
    // `type_values` も同じ扱い（OID4VP 1.0 の jwt_vc_json / jwt_vc_json-ld で必須のメタ）。
    // 外側・内側とも非空を要求する（空は「制約なし」ではなく不正）。
    const typeValues = ownProperty<unknown>(rawMeta, 'type_values');
    rejectOversized(typeValues, MAX_DCQL_ARRAY_LENGTH);
    if (typeValues !== undefined) {
      if (!isTypeValues(typeValues)) {
        throw new VericertsError(ErrorCodes.OID4VP_REQUEST_PARSE_FAILED);
      }
      for (const inner of typeValues) {
        rejectOversized(inner, MAX_DCQL_ARRAY_LENGTH);
      }
    }
    meta = {
      ...(vctValues !== undefined ? { vct_values: vctValues as readonly string[] } : {}),
      ...(typeValues !== undefined
        ? { type_values: typeValues as readonly (readonly string[])[] }
        : {}),
    };
  }

  let claims: readonly DcqlClaim[] | undefined;
  const rawClaims = ownProperty<unknown>(raw, 'claims');
  if (rawClaims !== undefined) {
    if (!Array.isArray(rawClaims)) {
      throw new VericertsError(ErrorCodes.OID4VP_REQUEST_PARSE_FAILED);
    }
    rejectOversized(rawClaims, MAX_DCQL_CLAIMS_PER_CREDENTIAL);
    claims = rawClaims.map(parseClaim);
  }

  const credential: DcqlCredential = {
    id,
    format,
    ...(meta !== undefined ? { meta } : {}),
    ...(claims !== undefined ? { claims } : {}),
  };
  return credential;
}

/**
 * DCQL クエリ（JSON object）をパース・構造検証する。
 *
 * この関数自体が**公開 SDK API**（`src/exports/auth.ts` からエクスポート）であり、SDK 内部の
 * 呼び出し元（`request.ts` の `decodeJsonParam` / `parseJarRequest`）のように `raw` が
 * `parseJsonWithoutPrototype` 由来の null プロトタイプであるとは限らない。利用者が通常の
 * `JSON.parse` の戻り値や手組みのオブジェクトリテラル（`Object.prototype` を継承）をそのまま
 * 渡し得るため、`raw` およびネストした `credentials[i]` / `credentials[i].meta` /
 * `credentials[i].claims[j]` の各メンバは own 限定・1 回読みで読む（`own-property.ts` の規約）。
 * 鎖読みのままだと、例えば `format` を持たないクレデンシャル要件でも
 * `Object.prototype.format` の汚染値が「指定された」ものとして扱われ、`8030` で拒否すべき
 * 不正なクエリ構造がパースを通過し得る。
 *
 * @param raw url-decode 済みの DCQL JSON object。
 * @returns 構造検証済み `DcqlQuery`。
 * 評価できない条件（クエリの `credential_sets`、要件の `claim_sets` / `trusted_authorities` /
 * `multiple`、`meta` の `vct_values` 以外のメンバ、空の `vct_values`）は黙って捨てずに fail-closed で
 * 拒否する（`context.reason: 'unsupported_dcql_member'`）。
 *
 * @throws `credentials` 欠落・型不正・必須フィールド欠落・評価未対応の条件があるとき（VericertsError、code `8030`）。
 */
export function parseDcqlQuery(raw: Record<string, unknown>): DcqlQuery {
  rejectUnsupportedMembers(raw, UNSUPPORTED_QUERY_MEMBERS);
  const rawCredentials = ownProperty<unknown>(raw, 'credentials');
  rejectOversized(rawCredentials, MAX_DCQL_CREDENTIALS);
  if (!Array.isArray(rawCredentials) || rawCredentials.length === 0) {
    throw new VericertsError(ErrorCodes.OID4VP_REQUEST_PARSE_FAILED);
  }
  const credentials = rawCredentials.map(parseCredential);

  // 要件 id の重複は曖昧なマッチ結果を生むため拒否する。
  const ids = new Set<string>();
  for (const credential of credentials) {
    if (ids.has(credential.id)) {
      throw new VericertsError(ErrorCodes.OID4VP_REQUEST_PARSE_FAILED, {
        context: { reason: 'duplicate_credential_id' },
      });
    }
    ids.add(credential.id);
  }
  return { credentials };
}
