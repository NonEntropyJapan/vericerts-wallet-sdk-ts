/**
 * W3C Verifiable Credential（VC）の JSON 構造検証・パース・シリアライズ。
 *
 * spec: W3C Verifiable Credentials Data Model v2.0。VC / VP 共有の `@context`
 * 検証（`assertVcV2Context`）・型定数・JSON パースの下請けは `vp.ts` にあり、本ファイルはそれらを
 * 使って VC 側の構造検証・パース・シリアライズに専念する（`vp.ts` から分離しているのはファイル行数
 * 上限（300 行）のため）。VP 側の対応する API は引き続き `vp.ts` にある。
 *
 * セキュリティ上の注意:
 * - 例外メッセージや `context` に VC 本文・開示値・JWT を含めない。
 */

import { ErrorCodes, VericertsError } from '../../errors.js';
import { ownProperty } from '../../prototype-safety/own-property.js';
import type { VerifiableCredential } from '../vc/vc.js';
import { assertVcV2Context, isNonEmptyStringArray, parseJsonStrict, VC_TYPE } from './vp.js';

// VC のパーサだけを取り込む利用者が、公開 index バレルを読み込まずに
// `parseVerifiableCredential` と両定数を同じモジュールから取得できるようにする。
export { VC_TYPE, VC_V2_CONTEXT } from './vp.js';

/**
 * 構造検証済みの VC と、**その検証に実際に使った own 値**。
 *
 * 呼び出し側が `vc.issuer` のように読み直すと、own アクセサ付きの VC を渡された場合に 2 度目が
 * 別の値を返し得る（TOCTOU: 検査した値と envelope↔body 突合に使う値が食い違う）。検証に使った
 * 値をそのまま下流へ渡せるよう、検査済みメンバを併せて返す（{@link AssertedVerifiablePresentation}
 * と同型）。
 */
export interface AssertedVerifiableCredential {
  /** 構造検証済みの VC（入力と同一参照）。 */
  readonly vc: VerifiableCredential;
  /** 検証に使った `issuer`（own 値）。 */
  readonly issuer: string;
  /** 検証に使った `credentialSubject`（own 値）。 */
  readonly credentialSubject: Readonly<Record<string, unknown>>;
  /** 検証に使った `issuanceDate`（own 値）。 */
  readonly issuanceDate: string;
  /** 検証に使った `expirationDate`（own 値。VC が持たなければ `undefined`）。 */
  readonly expirationDate?: string;
}

/** {@link AssertedVerifiableCredential} の VC 2.0 表現版（`validFrom` / `validUntil`）。 */
export interface AssertedVerifiableCredentialV2 {
  /** 構造検証済みの VC 本体（入力と同一参照）。 */
  readonly vc: Readonly<Record<string, unknown>>;
  /** 検証に使った `issuer`（own 値）。 */
  readonly issuer: string;
  /** 検証に使った `credentialSubject`（own 値）。 */
  readonly credentialSubject: Readonly<Record<string, unknown>>;
  /** 検証に使った `validFrom`（own 値）。 */
  readonly validFrom: string;
  /** 検証に使った `validUntil`（own 値。VC が持たなければ `undefined`）。 */
  readonly validUntil?: string;
}

/**
 * 任意の値（パース済み JSON 等）を `VerifiableCredential` として構造検証する。
 *
 * 必須プロパティ（`@context` / `type` / `issuer` / `credentialSubject` / `issuanceDate`）の存在と
 * 型・`@context` 先頭・`type` 先頭（`VerifiableCredential`）を検証する。任意の `expirationDate` も
 * 存在する場合は文字列であることを検証する（下流の日付変換に型不正な値を渡さないため）。妥当なら
 * 同一参照を VC として返す（コピーは行わない）。失効評価・スキーマ取得は責務外。
 *
 * 配列は VC ではないため明示的に拒否し、各メンバは**自身のプロパティに限って**読む
 * （`assertVerifiablePresentation` と同じ扱い）。
 *
 * 検査済みメンバを読み直さずに使いたい場合は {@link assertVerifiableCredentialMembers} を使う。
 *
 * @param value 検証対象の値（`parseVerifiableCredential` でのパース結果等）。
 * @returns 構造検証済みの `VerifiableCredential`。
 * @throws 構造不正の場合（VericertsError、code `3002`）。
 */
export function assertVerifiableCredential(value: unknown): VerifiableCredential {
  return assertVerifiableCredentialMembers(value).vc;
}

/**
 * 任意の値を `VerifiableCredential` として構造検証し、**検査済みメンバごと**返す。
 *
 * 検証内容は {@link assertVerifiableCredential} と同一。読み直し（TOCTOU）を避けたい呼び出し側は
 * 本関数を使い、返された `issuer` / `credentialSubject` / `issuanceDate` / `expirationDate` を
 * そのまま用いること（`vc/verify.ts` の `assertEnvelopeBinding`）。兄弟の
 * {@link assertVerifiablePresentationMembers} と同じ構造である。
 *
 * @param value 検証対象の値。
 * @returns 構造検証済みの VC と検査済みメンバ。
 * @throws 構造不正の場合（VericertsError、code `3002`）。
 */
export function assertVerifiableCredentialMembers(value: unknown): AssertedVerifiableCredential {
  const { issuer, credentialSubject, start, end } = assertCredentialMembers(
    value,
    'issuanceDate',
    'expirationDate',
  );
  return {
    vc: value as VerifiableCredential,
    issuer,
    credentialSubject,
    issuanceDate: start,
    expirationDate: end,
  };
}

/**
 * VC 2.0 の表現（`validFrom` / `validUntil`）の VC 本体を構造検証し、**検査済みメンバごと**返す。
 *
 * JWT-VC の `flat` 表現（payload 自体が VC 本体。`vc/jwt-vc-body.ts`）用。検証内容は
 * {@link assertVerifiableCredentialMembers} の `issuanceDate` / `expirationDate` を
 * `validFrom`（必須）/ `validUntil`（任意）に読み替えたもの。`validFrom` を必須とするのは、
 * envelope の `nbf` と束縛する日付を VC 1.1 側の `issuanceDate` と同じく常に持たせるためである。
 * VC 1.1 の命名（`issuanceDate` / `expirationDate`）はこの表現では読まない（束縛されない日付を
 * 受理しない）。
 *
 * @param value 検証対象の値（JWT payload）。
 * @returns 検査済みメンバ。
 * @throws 構造不正の場合（VericertsError、code `3002`）。
 */
export function assertVerifiableCredentialV2Members(
  value: unknown,
): AssertedVerifiableCredentialV2 {
  const { obj, issuer, credentialSubject, start, end } = assertCredentialMembers(
    value,
    'validFrom',
    'validUntil',
  );
  return { vc: obj, issuer, credentialSubject, validFrom: start, validUntil: end };
}

/**
 * VC 1.1 / 2.0 に共通の構造検証。日付メンバ名（開始・終了）だけを引数で切り替える。
 *
 * **配列を明示的に弾く。** `assertVerifiablePresentation` と同じ形に揃える。`typeof [] === 'object'`
 * かつ `parse-json.ts` の reviver は配列を素通しするため、配列は `Array.prototype` →
 * `Object.prototype` を保持したまま構造検証へ進み、全メンバを `Object.prototype` 汚染で満たせた。
 * VC は JSON オブジェクトであり配列ではない。各メンバも**自身のプロパティに限って**読む。
 */
function assertCredentialMembers(
  value: unknown,
  startKey: 'issuanceDate' | 'validFrom',
  endKey: 'expirationDate' | 'validUntil',
): {
  readonly obj: Record<string, unknown>;
  readonly issuer: string;
  readonly credentialSubject: Readonly<Record<string, unknown>>;
  readonly start: string;
  readonly end: string | undefined;
} {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new VericertsError(ErrorCodes.VC_SCHEMA_INVALID);
  }
  const obj = value as Record<string, unknown>;
  assertVcV2Context(ownProperty<unknown>(obj, '@context'));
  const type = ownProperty<unknown>(obj, 'type');
  if (!isNonEmptyStringArray(type) || type[0] !== VC_TYPE) {
    throw new VericertsError(ErrorCodes.VC_SCHEMA_INVALID);
  }
  const issuer = ownProperty<unknown>(obj, 'issuer');
  if (typeof issuer !== 'string' || issuer.length === 0) {
    throw new VericertsError(ErrorCodes.VC_SCHEMA_INVALID);
  }
  const start = ownProperty<unknown>(obj, startKey);
  if (typeof start !== 'string') {
    throw new VericertsError(ErrorCodes.VC_SCHEMA_INVALID);
  }
  // 終了日時は任意だが、**あるなら文字列**であることまで検証する。ここで narrow しないと
  // 下流（`verify.ts` の envelope↔body 突合 → `isoToNumericDate`）へ cast だけの値が届く。
  // パース境界で `null` プロトタイプ化された値は `toString` / `valueOf` を持たないため、
  // `Date.parse` の暗黙 `ToPrimitive` が `TypeError: No default value` になり、本 API の
  // 3002 の失敗面を迂回して生の例外が漏れる。
  const end = ownProperty<unknown>(obj, endKey);
  if (end !== undefined && typeof end !== 'string') {
    throw new VericertsError(ErrorCodes.VC_SCHEMA_INVALID);
  }
  const credentialSubject = ownProperty<unknown>(obj, 'credentialSubject');
  if (
    typeof credentialSubject !== 'object' ||
    credentialSubject === null ||
    Array.isArray(credentialSubject)
  ) {
    throw new VericertsError(ErrorCodes.VC_SCHEMA_INVALID);
  }
  return {
    obj,
    issuer,
    credentialSubject: credentialSubject as Readonly<Record<string, unknown>>,
    start,
    end,
  };
}

/**
 * JSON 文字列を `VerifiableCredential` としてパース・構造検証する。
 *
 * @param json VC を表す JSON 文字列。
 * @returns 構造検証済みの `VerifiableCredential`。
 * @throws JSON 解析不能 / 構造不正の場合（VericertsError、code `3002`）。
 */
export function parseVerifiableCredential(json: string): VerifiableCredential {
  return assertVerifiableCredential(parseJsonStrict(json));
}

/**
 * `VerifiableCredential` を JSON 文字列へシリアライズする。
 *
 * 構造検証を行ってからシリアライズする（不正な VC を出力しない）。`JSON.stringify` の標準挙動に従い、
 * プロパティ順は型定義に依存せず元 object のキー順となる（パースとのラウンドトリップは可能）。
 *
 * @param vc シリアライズ対象の VC。
 * @returns JSON 文字列。
 * @throws 構造不正の場合（VericertsError、code `3002`）。
 */
export function serializeVerifiableCredential(vc: VerifiableCredential): string {
  return JSON.stringify(assertVerifiableCredential(vc));
}
