/**
 * did:jwt の JWT デコード・JWK 変換・クレーム検証ヘルパ。
 *
 * メソッドプラグイン（`method-jwt.ts`）から共有される純粋関数群
 * （1 ファイル 300 行以下のため分割）。`jose` 等の JWT ライブラリは使わず base64url を
 * 自前で扱う。
 *
 * 対応署名アルゴリズム（`ES256` / `ES256K` / `EdDSA`）と公開鍵 JWK → 生バイト列の変換は
 * 兄弟モジュール `jwk-key.ts`（`ALG_SPECS` / `jwkToVerificationKey`）が担う。
 *
 * セキュリティ上の注意:
 * - 例外メッセージや `context` に DID 文字列・JWT・公開鍵などの入力データを含めない。
 */

import { base64urlnopad } from '@scure/base';
import { ErrorCodes, VericertsError } from '../../errors.js';
import { ownProperty } from '../../prototype-safety/own-property.js';
import { parseJsonWithoutPrototype } from '../../prototype-safety/parse-json.js';
import type { PublicKeyJwk, VerificationMethod } from '../did.js';

/** `did:jwt:` メソッドプレフィックス。 */
export const DID_JWT_PREFIX = 'did:jwt:';

/**
 * JWT を解決した DID Document に組み込む payload の最小構造。
 *
 * `id` と DID relationship 群は必須として扱い、`exp` / `nbf` は任意。
 */
export interface JwtPayload {
  readonly id?: unknown;
  readonly iss?: unknown;
  readonly sub?: unknown;
  readonly verificationMethod?: unknown;
  readonly authentication?: unknown;
  readonly assertionMethod?: unknown;
  readonly exp?: unknown;
  readonly nbf?: unknown;
}

/**
 * base64url（パディングなし）文字列をバイト列へデコードする。
 *
 * `@scure/base` の `base64urlnopad` に委ね、不正な文字列は DID 形式不正
 * （code `2001`）に正規化する。
 *
 * @param text base64url（パディングなし）文字列。
 * @returns デコードしたバイト列。
 * @throws base64url として不正な場合（VericertsError、code `2001`）。
 */
export function base64urlDecode(text: string): Uint8Array {
  try {
    return base64urlnopad.decode(text);
  } catch {
    // @scure/base 由来の例外は入力を含み得るため cause を渡さず正規化する。
    throw new VericertsError(ErrorCodes.INVALID_DID);
  }
}

/**
 * バイト列を UTF-8 文字列として解釈し、JSON をパースする。
 *
 * @param bytes JSON のバイト列。
 * @returns パース済みオブジェクト。
 * @throws UTF-8 / JSON として不正な場合（VericertsError、code `2001`）。
 */
export function parseJson(bytes: Uint8Array): Record<string, unknown> {
  try {
    const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    const value: unknown = parseJsonWithoutPrototype(text);
    if (typeof value !== 'object' || value === null || Array.isArray(value)) {
      throw new VericertsError(ErrorCodes.INVALID_DID);
    }
    return value as Record<string, unknown>;
  } catch (error) {
    if (error instanceof VericertsError) {
      throw error;
    }
    // 入力データはメッセージに含めない。
    throw new VericertsError(ErrorCodes.INVALID_DID);
  }
}

/**
 * JWS ヘッダに `crit`（RFC 7515 §4.1.11）が存在する場合に拒否する。
 *
 * `crit` は「列挙したヘッダパラメータを理解できない実装は JWS を無効として拒否せよ」という MUST を
 * 課す。本 SDK が理解する拡張は 0 個のため、**`crit` の存在自体**（空配列・不正型を含む。RFC 上も
 * 空配列は不正）を拒否する。理解しないまま `alg` と署名だけで受理すると、`b64: false` のような署名入力変更や
 * 独自の失効・用途限定拡張が黙って無視される。全 JWS ヘッダの共通経路（`decodeCompactJws` /
 * `resolveDidJwt`）から呼ばれる単一の実装。
 *
 * @param header デコード済み JWS ヘッダ。
 * @throws `crit` を持つ場合（VericertsError、code `2001`。各検証 API は呼び出し側の契約内コードへ正規化する）。
 */
export function assertNoCriticalHeaders(header: Record<string, unknown>): void {
  if (Object.hasOwn(header, 'crit')) {
    throw new VericertsError(ErrorCodes.INVALID_DID);
  }
}

/**
 * DID 主体クレーム（`id` / `iss` / `sub`）が did:jwt メソッドの DID であることを
 * 検証する。
 *
 * 存在する場合のみ検証し、文字列かつ `did:jwt:` プレフィックスを要求する。
 * 値の型が文字列でない、またはプレフィックスが異なる場合は DID 形式不正
 * （code `2001`）。省略は許容する。
 *
 * @param claim クレーム値（未検証）。
 * @throws 文字列でない / `did:jwt:` 始まりでない場合（VericertsError、code `2001`）。
 */
export function assertJwtDidClaim(claim: unknown): void {
  if (claim === undefined) {
    return;
  }
  if (typeof claim !== 'string' || !claim.startsWith(DID_JWT_PREFIX)) {
    throw new VericertsError(ErrorCodes.INVALID_DID);
  }
}

/**
 * payload の `verificationMethod[0]` を取得・検証する。
 *
 * @param payload デコード済み JWT payload。
 * @returns 先頭 VerificationMethod。
 * @throws `verificationMethod` が非空配列でない / 先頭要素が VerificationMethod
 *         でない / `publicKeyJwk` を持たない場合（VericertsError、code `2001`）。
 */
export function extractFirstVerificationMethod(
  payload: JwtPayload,
): VerificationMethod & { readonly publicKeyJwk: PublicKeyJwk } {
  const vms = payload.verificationMethod;
  if (!Array.isArray(vms) || vms.length === 0) {
    throw new VericertsError(ErrorCodes.INVALID_DID);
  }
  const first: unknown = vms[0];
  if (typeof first !== 'object' || first === null) {
    throw new VericertsError(ErrorCodes.INVALID_DID);
  }
  // 必須キーは own で読む。`Object.prototype.id` 等の汚染値で、キーを欠く要素が検査を通過するのを防ぐ。
  const vm = first as Partial<VerificationMethod>;
  const publicKeyJwk = ownProperty<unknown>(vm, 'publicKeyJwk');
  if (
    typeof ownProperty<unknown>(vm, 'id') !== 'string' ||
    typeof ownProperty<unknown>(vm, 'type') !== 'string' ||
    publicKeyJwk === undefined
  ) {
    throw new VericertsError(ErrorCodes.INVALID_DID);
  }
  if (typeof publicKeyJwk !== 'object' || publicKeyJwk === null) {
    throw new VericertsError(ErrorCodes.INVALID_DID);
  }
  // 戻り値の型は own の `publicKeyJwk` を検証済みであることを表す（利用側が鎖読みの `T | undefined` で読み直さない）。
  return vm as VerificationMethod & { readonly publicKeyJwk: PublicKeyJwk };
}

/**
 * `exp` / `nbf` クレームを評価する。
 *
 * `exp` / `nbf` は NumericDate（エポック秒）の数値とする。存在する場合のみ
 * 評価し、期限切れ（`now >= exp`）・有効化前（`now < nbf`）は DID 形式不正
 * （code `2001`）として失効扱いにする。型が数値でない場合も不正とする。
 *
 * @param payload デコード済み JWT payload。
 * @param nowSeconds 現在時刻（エポック秒）。
 * @throws 期限切れ・有効化前・型不正、または `nowSeconds` が有限数でない場合（VericertsError、code `2001`）。
 *         `NaN` は比較が常に `false` になり期限切れ・未発効を素通しする（fail-open）ため fail-closed に拒否する。
 */
export function evaluateTimeClaims(payload: JwtPayload, nowSeconds: number): void {
  if (!Number.isFinite(nowSeconds)) {
    throw new VericertsError(ErrorCodes.INVALID_DID);
  }
  if (payload.exp !== undefined) {
    if (typeof payload.exp !== 'number' || !Number.isFinite(payload.exp)) {
      throw new VericertsError(ErrorCodes.INVALID_DID);
    }
    if (nowSeconds >= payload.exp) {
      throw new VericertsError(ErrorCodes.INVALID_DID);
    }
  }
  if (payload.nbf !== undefined) {
    if (typeof payload.nbf !== 'number' || !Number.isFinite(payload.nbf)) {
      throw new VericertsError(ErrorCodes.INVALID_DID);
    }
    if (nowSeconds < payload.nbf) {
      throw new VericertsError(ErrorCodes.INVALID_DID);
    }
  }
}

/**
 * payload の DID relationship 群（`authentication` / `assertionMethod`）を
 * string 配列として取得する。
 *
 * 省略時は VerificationMethod の id 単独配列にフォールバックする。配列だが
 * string 以外を含む場合は不正とする。
 *
 * @param value payload の relationship 値。
 * @param fallbackId フォールバック時に使う VerificationMethod の id。
 * @returns string 参照の配列。
 * @throws 配列だが string 以外を含む場合（VericertsError、code `2001`）。
 */
export function toRelationshipRefs(value: unknown, fallbackId: string): readonly string[] {
  if (value === undefined) {
    return [fallbackId];
  }
  if (!Array.isArray(value)) {
    throw new VericertsError(ErrorCodes.INVALID_DID);
  }
  for (const entry of value) {
    if (typeof entry !== 'string') {
      throw new VericertsError(ErrorCodes.INVALID_DID);
    }
  }
  return value as readonly string[];
}
