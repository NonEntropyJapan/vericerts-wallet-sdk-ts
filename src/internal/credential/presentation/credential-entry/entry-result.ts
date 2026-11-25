/**
 * 内包 VC 1 件の検証結果の組み立てと、署名済み payload / ヘッダからのフィールド取り出し
 * （`credential-entry-verify.ts` から切り出し）。
 *
 * `VerificationResult` の形（未実行チェックの `null`・失敗時の `errors`）をこの 1 モジュールに
 * 集約し、JWT-VC / SD-JWT VC のどちらの経路からも同じ組み立てを使う。フォーマット別の検証本体は
 * `jwt-vc-entry.ts` / `sd-jwt-vc-entry.ts`、突合は `holder-binding.ts` にある。
 *
 * セキュリティ上の注意:
 * - `errors` にはエラーコードだけを入れ、VC 本文・開示値・JWT を含めない。
 * - payload / ヘッダは外部入力の JSON なので、フィールドは own 限定で読む（鎖読みすると
 *   当該キーを**持たない** VC で `Object.prototype` の汚染値を拾う）。
 */

import { type ErrorCode, ErrorCodes, VericertsError } from '../../../errors.js';
import { ownProperty } from '../../../prototype-safety/own-property.js';
import { buildTrustedIssuerIndex, isTrustedInIndex } from '../../../trusted-issuer/issuer-index.js';
import type { VCFormat } from '../../format-negotiation/types.js';
import { SD_JWT_VC_TYP, SD_JWT_VC_TYP_LEGACY } from '../../sdjwt/typ.js';
import { jwtVcBodyOf } from '../../vc/jwt-vc-body.js';
import type { EmbeddedCredentialVerifyInput, VerificationResult } from '../credential-results.js';
import { nowSecondsOf } from './entry-input.js';
import { verifyScopeOf } from './verify-scope.js';

/** チェック未実行フィールドの既定値（spec の `null` = 未実行）。`isTrustedIssuer` は個別に上書きする。 */
export const UNCHECKED = {
  isRevoked: null,
  isSuspended: null,
  isTrustedIssuer: null,
  schemaValid: null,
} as const;

/**
 * Trusted Issuer List 照合。
 *
 * `trustedIssuerList` が DI されていない、または `issuerDID` を取り出せなかった（空文字列）場合は
 * 「未実行」を表す `null` を返す（spec の既定挙動を維持する opt-in 設計。`credentialKey` /
 * `issuerTrust` と同じ「呼び出し側が明示的に渡した場合だけ判定する」パターン）。
 *
 * VC の種別（`credentialTypes`）を渡して発行者の対象種別制限を評価する: いずれかの種別が
 * エントリの `credentialTypes` に含まれれば信頼。種別を取り出せない（空、または相異なる種別が
 * `MAX_CREDENTIAL_TYPES` 超）場合は、`credentialTypes` で種別を制限したエントリを信頼せず
 * （fail-closed）、制限の無いエントリだけを照合対象にする。有効期間（`validFrom` / `validUntil`）は
 * VC 検証と同じ `nowSeconds` で評価する。
 *
 * **走査量は VP 全体で縛る。** リストは VP 検証 1 回につき発行者 DID で一度だけ索引化し
 * （`verify-scope.ts`）、各 VC は「その発行者のエントリ数 + 宣言種別数」だけを
 * 共有予算の `trustScans` に計上する。VC の `type` 件数にも、検証が失敗した VC の経路にも
 * 依存しない。超過は `VC_SCHEMA_INVALID`（3002、`reason: "work_budget_exceeded"`）の例外で、VP 全体を拒否する。
 */
export function trustedIssuerResultOf(
  input: Pick<EmbeddedCredentialVerifyInput, 'trustedIssuerList' | 'nowSeconds'>,
  issuerDID: string,
  credentialTypes: readonly string[],
): boolean | null {
  const list = ownProperty<EmbeddedCredentialVerifyInput['trustedIssuerList']>(
    input,
    'trustedIssuerList',
  );
  if (list === undefined || issuerDID === '') {
    return null;
  }
  // 索引と予算は `verifyEmbeddedCredentials` が VP ごとに 1 つ作る。スコープ外で直接呼ばれた場合だけ
  // ここで作る（予算は計上しない）。
  const scope = verifyScopeOf(input);
  return isTrustedInIndex(
    scope?.trustedIssuerIndex ?? buildTrustedIssuerIndex(list),
    issuerDID,
    credentialTypes,
    (nowSecondsOf(input) ?? Number.NaN) * 1000,
    scope?.budget,
  );
}

/**
 * JWT-VC の署名済み payload から VC 種別（VC 本体の `type`: 文字列または文字列配列）を取り出す。
 * VC 本体は `vc` claim か、VC 2.0 系の payload 自体（`vc/jwt-vc-body.ts`）。
 */
export function jwtVcTypesOf(payload: Record<string, unknown>): string[] {
  const { body: vc } = jwtVcBodyOf(payload);
  if (typeof vc !== 'object' || vc === null || Array.isArray(vc)) {
    return [];
  }
  const type = ownProperty<unknown>(vc, 'type');
  const types = Array.isArray(type) ? type : [type];
  return types.filter((t): t is string => typeof t === 'string');
}

/** SD-JWT VC の署名済み payload から VC 種別（`vct`）を取り出す。 */
export function sdJwtVcTypesOf(payload: Record<string, unknown>): string[] {
  const vct = ownProperty<unknown>(payload, 'vct');
  return typeof vct === 'string' ? [vct] : [];
}

/** 失敗結果を組み立てる。`credentialTypes` は取り出せた場合のみ渡す（無ければ種別制限エントリは信頼しない）。 */
export function failed(
  format: VCFormat,
  issuerDID: string,
  code: ErrorCode,
  input: EmbeddedCredentialVerifyInput,
  credentialTypes: readonly string[] = [],
): VerificationResult {
  return {
    valid: false,
    errors: [code],
    issuerDID,
    isExpired: false,
    format,
    ...UNCHECKED,
    isTrustedIssuer: trustedIssuerResultOf(input, issuerDID, credentialTypes),
  };
}

/** `VericertsError` ならそのコード、それ以外は署名検証不成立（3010）へ正規化する。 */
export function codeOf(error: unknown): ErrorCode {
  return error instanceof VericertsError ? error.code : ErrorCodes.SIG_INVALID;
}

/** デコード済み payload の `exp` から失効しているかを判定する（`exp` 欠落は `false`）。 */
export function isExpiredAt(
  payload: Record<string, unknown>,
  nowSeconds: number | undefined,
): boolean {
  // payload は外部入力の JSON。`exp` を**持たない** VC で継承値を拾うと、汚染値次第で
  // `isExpired` が反転する（結果オブジェクトの意味が呼び出し側から見て嘘になる）。
  const exp = ownProperty<unknown>(payload, 'exp');
  if (typeof exp !== 'number' || !Number.isFinite(exp)) {
    return false;
  }
  // 時計が非有限（NaN 等）だと比較が常に false になり失効を「有効」と表示してしまうため、
  // 判定不能は失効扱いに倒す（fail-closed）。
  return nowSeconds === undefined || !Number.isFinite(nowSeconds) || exp < nowSeconds;
}

/** JWS payload から発行者 DID（`iss`）を取り出す（取り出せなければ空文字列）。 */
export function issuerOf(payload: Record<string, unknown>): string {
  const iss = ownProperty<unknown>(payload, 'iss');
  return typeof iss === 'string' ? iss : '';
}

/** SD-JWT VC の提示部ヘッダ `typ` からフォーマット識別子を決める。 */
export function sdJwtFormatOf(header: Record<string, unknown>): VCFormat {
  return ownProperty<unknown>(header, 'typ') === SD_JWT_VC_TYP_LEGACY
    ? SD_JWT_VC_TYP_LEGACY
    : SD_JWT_VC_TYP;
}
