/**
 * W3C Verifiable Presentation（VP）のデータモデルと JSON 構造検証・パース。
 *
 * データモデルは W3C Verifiable Credentials Data Model v2.0 の VP に対応する。
 * SDK は `issuePresentation` / `verifyPresentation` で VP を JWT-VP（JWS）として署名・検証する。
 *
 * VP に含む `verifiableCredential` は JWT-VC（コンパクト JWS 文字列）または JSON-LD VC（object）の
 * 配列とする。本モジュールはその構造を検証する。内包 VC の署名検証は上位の VP 検証処理が行う。
 *
 * VC 側の構造検証・パース・シリアライズ（`assertVerifiableCredential` 等）は `vc-assert.ts` へ
 * 分離している（`vp.ts` から分離しているのはファイル行数上限（300 行）のため）。本
 * ファイルは VC / VP 共有の `@context` 検証（{@link assertVcV2Context}）・型定数・JSON パースの
 * 下請け（{@link parseJsonStrict}）を提供しつつ、VerifiablePresentation 側の型・検証・パース・
 * シリアライズに専念する。
 *
 * セキュリティ上の注意:
 * - 例外メッセージや `context` に VC 本文・開示値・JWT を含めない。
 */

import { ErrorCodes, VericertsError } from '../../errors.js';
import { assertCredentialCount } from '../../primitives/presentation-work-budget.js';
import { ownProperty } from '../../prototype-safety/own-property.js';
import { parseJsonWithoutPrototype } from '../../prototype-safety/parse-json.js';

/**
 * W3C VC Data Model v2.0 の base context（`@context` 先頭に必須）。
 *
 * VC / VP の `@context` 配列は本 URI を先頭要素として持つ必要がある（spec 準拠）。
 */
export const VC_V2_CONTEXT = 'https://www.w3.org/ns/credentials/v2' as const;

/** W3C VP の `type` 先頭に必須の型名。 */
export const VP_TYPE = 'VerifiablePresentation' as const;

/** W3C VC の `type` 先頭に必須の型名。 */
export const VC_TYPE = 'VerifiableCredential' as const;

/**
 * W3C Verifiable Presentation のデータモデル（最小）。
 *
 * `verifiableCredential` は JWT-VC（コンパクト JWS 文字列）または JSON-LD VC（object）の配列。
 * `holder` は提示者 DID 文字列。JWT-VP として署名する際、`holder` は `iss`、`id` は `jti` に対応する。
 */
export interface VerifiablePresentation {
  /** JSON-LD コンテキスト（先頭は W3C VC v2 の base context）。 */
  readonly '@context': readonly string[];
  /** VP の type（先頭は `VerifiablePresentation`）。 */
  readonly type: readonly string[];
  /** 提示者 DID 文字列。JWT-VP の `iss` に対応する。 */
  readonly holder: string;
  /** 提示する VC の配列（JWT-VC 文字列 / JSON-LD VC object）。 */
  readonly verifiableCredential: ReadonlyArray<string | Readonly<Record<string, unknown>>>;
  /** VP の ID（URI）。JWT-VP の `jti` に対応する。 */
  readonly id?: string;
}

/**
 * `@context` 配列の先頭が W3C VC v2 base context であることを検証する。
 *
 * W3C VC Data Model v2.0 は `@context` の先頭要素を base context に固定する。先頭以外の追加
 * context は許容する。空配列・先頭不一致・要素が文字列でない場合は構造不正（3002）として拒否する。
 *
 * VC（`vc-assert.ts`）と VP（本ファイル）の両方から共有される。
 *
 * @param context 検証対象の `@context` 値（未知の入力でもよい）。
 * @throws 先頭が base context でない / 配列でない場合（VericertsError、code `3002`）。
 */
export function assertVcV2Context(context: unknown): void {
  if (!Array.isArray(context) || context[0] !== VC_V2_CONTEXT) {
    // 入力（context 値）はメッセージに含めず構造不正へ正規化する。
    throw new VericertsError(ErrorCodes.VC_SCHEMA_INVALID);
  }
}

/**
 * 値が「文字列要素のみの非空配列」かを判定する。
 *
 * VC（`vc-assert.ts`）と VP（本ファイル）の `type` 検証で共有される。
 */
export function isNonEmptyStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.length > 0 && value.every((v) => typeof v === 'string');
}

/**
 * 構造検証済みの VP と、**その検証に実際に使った own 値**。
 *
 * 呼び出し側が `vp.holder` のように読み直すと、own アクセサ付きの VP を渡された場合に 2 度目が
 * 別の値を返し得る（TOCTOU: 突合に使った DID と結果として報告する DID が食い違う）。検証に
 * 使った値をそのまま下流へ渡せるよう、検査済みメンバを併せて返す。
 */
export interface AssertedVerifiablePresentation {
  /** 構造検証済みの VP（入力と同一参照）。 */
  readonly vp: VerifiablePresentation;
  /** 検証に使った `holder`（own 値）。 */
  readonly holder: string;
  /** 検証に使った `verifiableCredential`（own 値）。 */
  readonly verifiableCredential: ReadonlyArray<string | Readonly<Record<string, unknown>>>;
}

/**
 * 任意の値（パース済み JSON 等）を `VerifiablePresentation` として構造検証する。
 *
 * 必須プロパティ（`@context` / `type` / `holder` / `verifiableCredential`）の存在と型・`@context`
 * 先頭・`type` 先頭（`VerifiablePresentation`）を検証する。`verifiableCredential` は文字列（JWT-VC）
 * または非配列 object（JSON-LD VC）の配列であること（空配列も許容。配列要素や `null` は拒否する）。
 * 含まれる各 VC の中身は検証しない。
 *
 * 検査済みメンバを読み直さずに使いたい場合は {@link assertVerifiablePresentationMembers} を使う。
 *
 * @param value 検証対象の値。
 * @returns 構造検証済みの `VerifiablePresentation`。
 * @throws 構造不正の場合（VericertsError、code `3002`）。
 */
export function assertVerifiablePresentation(value: unknown): VerifiablePresentation {
  return assertVerifiablePresentationMembers(value).vp;
}

/**
 * 任意の値を `VerifiablePresentation` として構造検証し、**検査済みメンバごと**返す。
 *
 * 検証内容は {@link assertVerifiablePresentation} と同一。読み直し（TOCTOU）を避けたい呼び出し側は
 * 本関数を使い、返された `holder` / `verifiableCredential` をそのまま用いること。
 *
 * @param value 検証対象の値。
 * @returns 構造検証済みの VP と検査済みメンバ。
 * @throws 構造不正の場合（VericertsError、code `3002`）。
 */
export function assertVerifiablePresentationMembers(
  value: unknown,
): AssertedVerifiablePresentation {
  // **配列を明示的に弾く。** `typeof [] === 'object'` なので従来は配列が構造検証へ進み、
  // しかも配列は `parse-json.ts` の reviver が素通しするため `Array.prototype` →
  // `Object.prototype` を保持する。結果、下の 4 つの構造検査を鎖読みで満たせた:
  // payload が `{"iss":"<提示者 DID>","vp":[]}` の**署名済み** JWT-VP が、
  // `Object.prototype` の `@context` / `type` / `holder` / `verifiableCredential` 汚染で
  // 構造検証を通り（`holder` を `iss` と同じ DID にすれば Holder Binding ゲートも通り）、
  // **呼び出し側へ返る内包 VC リストが丸ごと `Object.prototype` 由来＝ JWT 署名に一切
  // 覆われない**状態になった（fail-open）。VP は JSON オブジェクトであり配列ではない。
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new VericertsError(ErrorCodes.VC_SCHEMA_INVALID);
  }
  // 各メンバも**自身のプロパティに限って**読む。全メンバを `ownProperty` で読み、
  // 配列ケースでも fail-closed とする。
  const obj = value as Record<string, unknown>;
  assertVcV2Context(ownProperty<unknown>(obj, '@context'));
  const type = ownProperty<unknown>(obj, 'type');
  if (!isNonEmptyStringArray(type) || type[0] !== VP_TYPE) {
    throw new VericertsError(ErrorCodes.VC_SCHEMA_INVALID);
  }
  const holder = ownProperty<unknown>(obj, 'holder');
  if (typeof holder !== 'string' || holder.length === 0) {
    throw new VericertsError(ErrorCodes.VC_SCHEMA_INVALID);
  }
  const verifiableCredential = ownProperty<unknown>(obj, 'verifiableCredential');
  if (
    !Array.isArray(verifiableCredential) ||
    !verifiableCredential.every(
      (c) => typeof c === 'string' || (typeof c === 'object' && c !== null && !Array.isArray(c)),
    )
  ) {
    throw new VericertsError(ErrorCodes.VC_SCHEMA_INVALID);
  }
  // 件数は署名検証・DID 解決・chain 走査のどれよりも前に縛る（chain 側 共通の上限）。
  assertCredentialCount(verifiableCredential.length);
  return { vp: value as VerifiablePresentation, holder, verifiableCredential };
}

/**
 * JSON 文字列を `VerifiablePresentation` としてパース・構造検証する。
 *
 * @param json VP を表す JSON 文字列。
 * @returns 構造検証済みの `VerifiablePresentation`。
 * @throws JSON 解析不能 / 構造不正の場合（VericertsError、code `3002`）。
 */
export function parseVerifiablePresentation(json: string): VerifiablePresentation {
  return assertVerifiablePresentation(parseJsonStrict(json));
}

/**
 * `VerifiablePresentation` を JSON 文字列へシリアライズする。
 *
 * @param vp シリアライズ対象の VP。
 * @returns JSON 文字列。
 * @throws 構造不正の場合（VericertsError、code `3002`）。
 */
export function serializeVerifiablePresentation(vp: VerifiablePresentation): string {
  return JSON.stringify(assertVerifiablePresentation(vp));
}

/**
 * JSON 文字列を厳格にパースする。解析不能な場合は構造不正（3002）へ正規化する。
 *
 * `JSON.parse` 由来の例外は入力本文を含み得るため cause を渡さない。
 * VC（`vc-assert.ts`）と VP（本ファイル）のパースから共有される。
 *
 * @param json パース対象の JSON 文字列。
 * @returns パース結果（未知の値）。
 * @throws JSON として解析できない場合（VericertsError、code `3002`）。
 */
export function parseJsonStrict(json: string): unknown {
  try {
    return parseJsonWithoutPrototype(json);
  } catch {
    throw new VericertsError(ErrorCodes.VC_SCHEMA_INVALID);
  }
}
