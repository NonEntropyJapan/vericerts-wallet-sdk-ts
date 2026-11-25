/**
 * 受領した SD-JWT VC の復号（クレーム復元）と PID Rulebook 検証結果のエラー写像。
 *
 * `receive.ts` の OID4VCI 通信部（Offer → Metadata → Token → Credential）と、受領後の
 * 「バイト列を解釈して検証する」部分は攻撃面も失敗コードも異なる（前者は 3003 / 3004 / 8010 /
 * 8020、後者は 8020 / 10001 / 10002 / 10003）。1 ファイルに同居させると、どの失敗がどちらの
 * 面に属するかが読み取れなくなるため分割する。
 *
 * **署名検証は本モジュールの責務ではない。** ここで行うのは Issuer-signed JWT の payload 取り出しと
 * Disclosure の digest 照合（`recoverClaims`）までで、Issuer 署名の検証・失効確認は呼び出し側
 * （wallet facade の `verifyCredential` 経路）が担う。`receive.ts` はこの分担を前提に、
 * 受領した生 SD-JWT を `raw` として保持したまま返す。
 *
 * セキュリティ上の注意:
 * - 例外の `context` に**クレーム値・属性パス・vct・JWT を一切載せない**（PID の属性値は PII）。
 *   固定の識別子のみを載せる。
 */

import { recoverClaims } from '../../../credential/sdjwt/claims.js';
import { parseSdJwt } from '../../../credential/sdjwt/sdjwt.js';
import { decodeCompactJwsOrThrow } from '../../../credential/vc/jws.js';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import type { PIDCredential, SchemaError } from '../../../eudi/pid/index.js';
import { validatePIDSchema } from '../../../eudi/pid/index.js';
import { defineDataProperty } from '../../../prototype-safety/define-data-property.js';
import { ownProperty } from '../../../prototype-safety/own-property.js';

/**
 * 属性集合から除外する SD-JWT VC の構造クレーム。
 *
 * `PIDClaims` / `EAACredential.claims` は「ユーザー属性の集合」であり、型識別子（`vct`）・
 * Holder バインド（`cnf`）・失効参照（`status`）・JWT の登録済みクレームは属性ではない。
 * 残したままにすると `presentEAACredential` が「全 top-level クレームを開示する」際にこれらを
 * 開示対象名として扱うことになり、意図が読めなくなる。
 */
const STRUCTURAL_CLAIMS: ReadonlySet<string> = new Set([
  'vct',
  'cnf',
  'status',
  'iss',
  'sub',
  'iat',
  'exp',
  'nbf',
]);

/**
 * 受領した SD-JWT VC を解釈した結果。
 *
 * @experimental 挙動・シグネチャが変わり得る（v1.0 で `@stable` 昇格予定）。
 */
export interface DecodedCredential {
  /** 型識別子（`vct` クレーム）。存在しない / 文字列でなければ `undefined`。 */
  readonly vct: string | undefined;
  /** 発行者識別子（`iss` クレーム）。存在しない / 文字列でなければ `undefined`。Catalogue の `issuerAllowList` 照合に使う。 */
  readonly iss: string | undefined;
  /** 構造クレームを除いた属性集合（`null` プロトタイプ）。 */
  readonly claims: Record<string, unknown>;
}

/**
 * 受領した SD-JWT VC を解釈し、`vct` と復元済み属性集合を取り出す。
 *
 * 分解（`parseSdJwt`）→ Issuer-signed JWT の payload 取り出し（`decodeCompactJwsOrThrow`）→
 * Disclosure の digest 照合と復元（`recoverClaims`）を行う。いずれの段階の失敗も
 * `CREDENTIAL_REQUEST_FAILED`（8020）へ正規化する。発行者から受け取ったバイト列が解釈できない
 * こと自体が受領の失敗であり、内訳（どの段で落ちたか）を呼び出し側へ伝えると受領した VC の
 * 中身を推測させる材料になるため、単一の理由へ畳む。
 *
 * 戻り値の `claims` は `Object.create(null)` 上に `defineDataProperty` で組む。素朴な代入だと
 * クレーム名 `__proto__` が own プロパティを作らずプロトタイプを差し替え、**そのクレームが
 * 無言で消える**うえ返した集合が攻撃者の選んだオブジェクトを継承する（`sdjwt/claims.ts` の
 * `defineClaim` と同じ理由）。
 *
 * @param raw 受領した SD-JWT VC コンパクト表現。
 * @returns `vct` / `iss` と構造クレームを除いた属性集合。
 * @throws 分解・復元に失敗した場合（VericertsError、code `8020`）。
 *
 * @experimental 挙動・シグネチャが変わり得る（v1.0 で `@stable` 昇格予定）。
 */
export function decodeReceivedCredential(raw: string): DecodedCredential {
  let recovered: Record<string, unknown>;
  try {
    const parts = parseSdJwt(raw);
    const decoded = decodeCompactJwsOrThrow(parts.issuerJwt, ErrorCodes.CREDENTIAL_REQUEST_FAILED);
    recovered = recoverClaims(decoded.payload, parts);
  } catch {
    // VC 本文・Disclosure を載せないため cause は渡さない。
    throw new VericertsError(ErrorCodes.CREDENTIAL_REQUEST_FAILED, {
      context: { reason: 'credential_decode_failed' },
    });
  }
  // `recovered` は `recoverClaims` が `Object.create(null)` で組むため鎖読みの穴は無いが、
  // own 限定読みを重ねる（多層防御。`own-property.ts`「削ってはならない」）。
  const vct = ownProperty<unknown>(recovered, 'vct');
  const iss = ownProperty<unknown>(recovered, 'iss');
  const claims: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
  for (const [name, value] of Object.entries(recovered)) {
    if (!STRUCTURAL_CLAIMS.has(name)) {
      defineDataProperty(claims, name, value);
    }
  }
  return {
    vct: typeof vct === 'string' ? vct : undefined,
    iss: typeof iss === 'string' ? iss : undefined,
    claims,
  };
}

/**
 * PID Rulebook 検証の失敗を 10002 / 10001 のどちらへ写すかを判定する。
 *
 * `SchemaError.required` は PID Rulebook の必須属性に対する違反かを表す。
 * `validatePIDSchema` は `vct` の不一致にも `required: true` を立てる
 * ため、**`path === 'vct'` の違反は 10002 の判定から除外する**。`vct` 不一致は
 * 「必須属性が欠けている」のではなく「そもそも PID ではない SD-JWT VC を渡された」= スキーマ
 * 違反であり、`PID_REQUIRED_ATTR_MISSING`（10002）に写すと呼び出し側が「PID の属性を補えば
 * 解決する」と誤解する。したがって `vct` 起因は `PID_SCHEMA_INVALID`（10001）に倒す。
 */
function hasMissingMandatoryAttribute(errors: readonly SchemaError[]): boolean {
  return errors.some(
    (error) =>
      ownProperty<boolean>(error, 'required') === true &&
      ownProperty<string>(error, 'path') !== 'vct',
  );
}

/**
 * `validatePIDSchema` の結果を検査し、違反があれば対応するエラーへ写して投げる。
 *
 * `validatePIDSchema` は例外を投げず `SchemaValidationResult` を返す契約のため、
 * 受領フロー側で `valid === false` を検知して `VericertsError` へ変換する責務がここにある。
 *
 * - 必須属性に対する違反（`required: true` かつ `path !== 'vct'`）が 1 件でもあれば
 *   `PID_REQUIRED_ATTR_MISSING`（10002）。
 * - それ以外（任意属性の型・形式違反 / `vct` 不一致）は `PID_SCHEMA_INVALID`（10001）。
 *
 * `context` に**属性名も属性値も載せない**。PID の属性値は PII であり、属性パスも
 * 「どの属性を持っているか」という情報になるため。
 *
 * @param pid 検証対象の PID Credential。
 * @throws 必須属性の違反がある場合（code `10002`）、その他のスキーマ違反の場合（code `10001`）。
 *
 * @experimental 挙動・シグネチャが変わり得る（v1.0 で `@stable` 昇格予定）。
 */
export function assertPIDSchemaValid(pid: PIDCredential): void {
  const result = validatePIDSchema(pid);
  if (result.valid) {
    return;
  }
  // 失敗結果は `{ valid: false, errors }` として組まれるが、`errors` を own 限定で読む
  // （`schema.ts` が同じ理由で own 限定にしているのと対称）。
  const errors = ownProperty<readonly SchemaError[]>(result, 'errors') ?? [];
  throw new VericertsError(
    hasMissingMandatoryAttribute(errors)
      ? ErrorCodes.PID_REQUIRED_ATTR_MISSING
      : ErrorCodes.PID_SCHEMA_INVALID,
  );
}
