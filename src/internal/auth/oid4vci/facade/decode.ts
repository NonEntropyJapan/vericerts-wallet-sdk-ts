/**
 * 受領した生 VC を `ReceivedVerifiableCredential`へ解釈する。
 *
 * SD-JWT VC と JWT-VC のクレームを受領結果の各フィールドに対応付け、生の VC を `raw` に残す。
 *
 * **`claims` の出所はフォーマットで異なる**。SD-JWT VC は復元済み payload の直下から
 * 構造クレームを引いたもの、W3C JWT-VC は `vc.credentialSubject` 配下である（`toClaims` /
 * `toJwtVcClaims`）。
 *
 * **署名検証は行わない。** ここで行うのは Issuer-signed JWT の payload 取り出しと Disclosure の
 * digest 照合（`recoverClaims`）までである（`receive.ts` の `deps.verifyReceived` が担う）。
 *
 * セキュリティ上の注意:
 * - 例外の `context` に**クレーム値・属性パス・vct・JWT を一切載せない**（属性値は PII）。
 * - `claims` は `Object.create(null)` 上に `defineDataProperty` で組む。素朴な代入だと
 *   クレーム名 `__proto__` が own プロパティを作らずプロトタイプを差し替え、**そのクレームが
 *   無言で消える**うえ返した集合が攻撃者の選んだオブジェクトを継承する。
 */

import { recoverClaims } from '../../../credential/sdjwt/claims.js';
import { parseSdJwt } from '../../../credential/sdjwt/sdjwt.js';
import { decodeCompactJwsOrThrow } from '../../../credential/vc/jws.js';
import { jwtVcBodyOf } from '../../../credential/vc/jwt-vc-body.js';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import { defineDataProperty } from '../../../prototype-safety/define-data-property.js';
import { isNonBlankString } from '../../../prototype-safety/non-empty-string.js';
import { ownProperty } from '../../../prototype-safety/own-property.js';
import type { ReceivedVerifiableCredential, VCFormat } from './types.js';

/**
 * 属性集合から除外する構造クレーム（**SD-JWT VC 経路のみで使う**）。
 *
 * `claims` は「ユーザー属性の集合」であり、型識別子（`vct`）・Holder バインド（`cnf`）・
 * 失効参照（`status`）・JWT の登録済みクレームは属性ではない（`eudi/issuance/decode.ts` の
 * `STRUCTURAL_CLAIMS` と同じ範囲に `vc` / `jti` / `aud` を加える）。
 *
 * JWT-VC は属性の**所在そのものが違う**（`vc.credentialSubject` 配下）ため、この除外集合では
 * なく {@link toJwtVcClaims} を使う。
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
  'jti',
  'aud',
  'vc',
]);

/** 復号の失敗を `CREDENTIAL_REQUEST_FAILED`（8020）へ正規化する。 */
function decodeFailure(reason: string): VericertsError {
  return new VericertsError(ErrorCodes.CREDENTIAL_REQUEST_FAILED, { context: { reason } });
}

/** Unix 秒（数値）を ISO 8601 へ写す。数値でなければ `undefined`。 */
function toIsoDate(value: unknown): string | undefined {
  if (typeof value !== 'number' || !Number.isFinite(value)) {
    return undefined;
  }
  const date = new Date(value * 1000);
  return Number.isNaN(date.getTime()) ? undefined : date.toISOString();
}

/** 空の属性集合（`null` プロトタイプ）を作る。 */
function emptyClaims(): Record<string, unknown> {
  return Object.create(null) as Record<string, unknown>;
}

/**
 * SD-JWT VC の属性集合を組む（復元済み payload から構造クレームを除く）。
 *
 * SD-JWT VC は属性を payload 直下に置く（`_sd` の digest から復元した Disclosure も
 * `recoverClaims` が直下へ戻す）ため、除外集合を引くだけで属性が得られる。
 */
function toClaims(payload: Record<string, unknown>): Record<string, unknown> {
  const claims = emptyClaims();
  for (const [name, value] of Object.entries(payload)) {
    if (!STRUCTURAL_CLAIMS.has(name)) {
      defineDataProperty(claims, name, value);
    }
  }
  return claims;
}

/**
 * W3C JWT-VC の属性集合を `vc.credentialSubject` から組む。
 *
 * **属性は payload 直下には存在しない。** W3C JWT-VC は VC 本体を `vc` に入れ、属性はすべて
 * `vc.credentialSubject` 配下に置く（本 SDK 自身の `credential/vc/issue.ts` も payload を
 * `{ iss, nbf, iat, vc }` として組み、`sub` は `vc.credentialSubject.id` の写しである）。
 * したがって直下から構造クレームを引く SD-JWT VC 用の写像を JWT-VC に適用すると、
 * **属性が丸ごと落ちて `claims` が `{}` になる**（例外も出ない無言の欠落）。
 *
 * `credentialSubject.id` は除く。これは **Holder（subject）の識別子であって属性ではない**ため
 * であり、SD-JWT VC 経路が `sub` を {@link STRUCTURAL_CLAIMS} として除くのと同じ扱いである
 * （必要な呼び出し側は `raw` から読む）。
 *
 * `credentialSubject` を**持たない / オブジェクトでない / 配列**の JWT-VC は**空の `claims` を
 * 返す**（これが仕様どおりの挙動である）。属性の所在は `vc.credentialSubject` だけなので他所
 * から拾うと「W3C VC が属性と定めていない値を属性として報告する」ことになり、配列形（複数
 * subject）は平坦な `claims` に一意へ写せない（`"0"` のような添字キーになる）。型を判別できない
 * 場合（{@link resolveTypes}）と違い、属性が 0 件であること自体は受領の失敗ではない。
 */
function toJwtVcClaims(vc: object): Record<string, unknown> {
  const claims = emptyClaims();
  const subject = ownProperty<unknown>(vc, 'credentialSubject');
  if (typeof subject !== 'object' || subject === null || Array.isArray(subject)) {
    return claims;
  }
  // `Object.entries` は own の列挙プロパティだけを返す（継承値は拾わない）。
  for (const [name, value] of Object.entries(subject)) {
    if (name !== 'id') {
      defineDataProperty(claims, name, value);
    }
  }
  return claims;
}

/**
 * 受領した VC の payload を取り出す。
 *
 * SD-JWT VC（`~` を含む）は分解して Disclosure を復元し、素の JWT-VC はそのまま payload を
 * 取り出す。判定を `~` の有無で行うのは、SD-JWT のコンパクト直列化が Disclosure を `~` で
 * 連結すると定めるためである（開示が 0 件でも末尾に `~` が付く）。
 */
function decodePayload(raw: string): { payload: Record<string, unknown>; format: VCFormat } {
  if (raw.includes('~')) {
    const parts = parseSdJwt(raw);
    const decoded = decodeCompactJwsOrThrow(parts.issuerJwt, ErrorCodes.CREDENTIAL_REQUEST_FAILED);
    return { payload: recoverClaims(decoded.payload, parts), format: 'sd-jwt' };
  }
  const decoded = decodeCompactJwsOrThrow(raw, ErrorCodes.CREDENTIAL_REQUEST_FAILED);
  return { payload: decoded.payload, format: 'jwt' };
}

/**
 * VC 本体（JWT-VC の `vc` claim、または VC 2.0 系 JWT-VC の payload 自体）を own 限定で 1 度だけ読む。
 * オブジェクトでなければ `undefined`。
 *
 * 鎖読みだと `vc` を持たない SD-JWT VC が `Object.prototype.vc` の汚染値から型・識別子・属性を
 * 拾う。読みを 1 か所に集約することで、own アクセサ付きの payload を渡されても型・識別子・
 * 属性が別々の `vc` を見る余地が無くなる。
 *
 * `format: 'jwt'` のとき、`vc` を持たず own の `@context` を持つ payload は VC 2.0 系（walt.id 等が
 * `vc` で包まずに出す表現。`jwt-vc-body.ts`）で、payload 自体が VC 本体である。
 * SD-JWT VC には適用しない（SD-JWT VC は型を `vct` で持ち、`vc` の有無で表現を切り替えない）。
 */
function vcObject(payload: Record<string, unknown>, format: VCFormat): object | undefined {
  if (format === 'jwt') {
    const { form, body } = jwtVcBodyOf(payload);
    if (form === 'flat') {
      return payload;
    }
    return typeof body === 'object' && body !== null ? body : undefined;
  }
  const vc = ownProperty<unknown>(payload, 'vc');
  return typeof vc === 'object' && vc !== null ? vc : undefined;
}

/**
 * `type` 列を決める。
 *
 * SD-JWT VC は型識別子が `vct` の 1 値、JWT-VC は W3C VC Data Model の `vc.type` 配列である。
 * どちらも取れない場合は「型が判別できない VC」であり、呼び出し側が
 * 保存先も検証方法も決められないため受領の失敗に倒す（fail-closed）。
 */
function resolveTypes(payload: Record<string, unknown>, vc: object | undefined): readonly string[] {
  const vct = ownProperty<unknown>(payload, 'vct');
  if (isNonBlankString(vct)) {
    return [vct];
  }
  if (vc !== undefined) {
    const types = ownProperty<unknown>(vc, 'type');
    if (Array.isArray(types) && types.every((t) => isNonBlankString(t))) {
      return types as readonly string[];
    }
  }
  throw decodeFailure('credential_type_missing');
}

/**
 * VC の識別子を決める。
 *
 * `jti`（JWT の登録済みクレーム）を優先し、無ければ JWT-VC の `vc.id` へ落とす。後者は
 * W3C VC Data Model の標準形であり、`jti` を持たない JWT-VC で識別子を無言に落とすと
 * 呼び出し側が VC を一意に指せなくなる（保存済み VC の更新・失効照合が壊れる）。
 *
 * `vc` は {@link vcObject} が own 限定で読んだものを受け取る（`resolveTypes` / `toJwtVcClaims`
 * と同じ 1 度の読みを共有する）。どちらも取れない場合は `undefined` を返す。
 */
function resolveId(payload: Record<string, unknown>, vc: object | undefined): string | undefined {
  const jti = ownProperty<unknown>(payload, 'jti');
  if (isNonBlankString(jti)) {
    return jti;
  }
  if (vc !== undefined) {
    const id = ownProperty<unknown>(vc, 'id');
    if (isNonBlankString(id)) {
      return id;
    }
  }
  return undefined;
}

/**
 * 受領した生 VC を `ReceivedVerifiableCredential` へ変換する。
 *
 * @param raw 受領した VC のコンパクト表現（SD-JWT VC または JWT-VC）。
 * @returns 形式・クレーム・発行者などを含む受領結果。`raw` は入力そのまま。
 * @throws 分解・復元に失敗した場合、`iss` / 型 / 発行日時が取れない場合
 *         （VericertsError、code `8020`）。
 */
export function toReceivedCredential(raw: string): ReceivedVerifiableCredential {
  let payload: Record<string, unknown>;
  let format: VCFormat;
  try {
    const decoded = decodePayload(raw);
    payload = decoded.payload;
    format = decoded.format;
  } catch {
    // VC 本文・Disclosure を載せないため cause は渡さない。
    throw decodeFailure('credential_decode_failed');
  }
  // `recoverClaims` / `decodeCompactJwsOrThrow` の戻り値は `null` プロトタイプだが、own 限定読みを
  // 重ねる（多層防御。`own-property.ts`「削ってはならない」）。
  const issuer = ownProperty<unknown>(payload, 'iss');
  if (!isNonBlankString(issuer)) {
    throw decodeFailure('credential_issuer_missing');
  }
  const vc = vcObject(payload, format);
  const type = resolveTypes(payload, vc);
  // 発行日時は `iat`、無ければ `nbf`（RFC 7519。SD-JWT VC は `iat` を推奨するが必須ではない）。
  const issuanceDate =
    toIsoDate(ownProperty(payload, 'iat')) ?? toIsoDate(ownProperty(payload, 'nbf'));
  if (issuanceDate === undefined) {
    throw decodeFailure('credential_issuance_date_missing');
  }
  const expirationDate = toIsoDate(ownProperty(payload, 'exp'));
  const id = resolveId(payload, vc);
  // 属性の出所はフォーマットで異なる。SD-JWT VC は復元済み payload 直下、
  // W3C JWT-VC は `vc.credentialSubject` 配下。`format` も併せて見るのは、SD-JWT VC 経路の
  // 挙動を「`vc` というクレーム名がたまたま入っていた」だけで切り替えないためである。
  const claims = format === 'jwt' && vc !== undefined ? toJwtVcClaims(vc) : toClaims(payload);
  return {
    ...(id === undefined ? {} : { id }),
    type,
    issuer,
    issuanceDate,
    ...(expirationDate === undefined ? {} : { expirationDate }),
    claims,
    raw,
    format,
  };
}
