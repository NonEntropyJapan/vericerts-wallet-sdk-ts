/**
 * 高レベル Verifier API（判別共用体 Result 型）をテストから扱うための小道具。
 *
 * `valid` で判別する型なので、テスト側は「期待した枝であること」を明示してから中身を見る必要がある。
 * 各テストで `if (!result.valid) throw ...` を書くと本題が埋もれるため、ここへ集約する。
 */

import type {
  CredentialVerificationResult,
  EmbeddedCredentialVerificationResult,
  PresentationVerificationResult,
  VerificationIssue,
} from '../../internal/credential/index.js';

/** `VerificationIssue[]` からコードだけを取り出す（順序は保つ）。 */
export function issueCodes(issues: readonly VerificationIssue[]): string[] {
  return issues.map((issue) => issue.code);
}

/** 内包 VC 1 件の失敗コードを取り出す（成功 / 未定義なら空配列）。 */
export function embeddedErrorCodes(
  result: EmbeddedCredentialVerificationResult | undefined,
): string[] {
  return result === undefined || result.valid ? [] : issueCodes(result.errors);
}

/** VP の結果が `valid: true` の枝であることを確かめて返す（違えば失敗理由付きで throw）。 */
export function assertPresentationValid(
  result: PresentationVerificationResult,
): Extract<PresentationVerificationResult, { valid: true }> {
  if (!result.valid) {
    throw new Error(`expected valid presentation, got errors: ${issueCodes(result.errors).join()}`);
  }
  return result;
}

/** VP の結果が `valid: false` の枝であることを確かめて返す。 */
export function assertPresentationInvalid(
  result: PresentationVerificationResult,
): Extract<PresentationVerificationResult, { valid: false }> {
  if (result.valid) {
    throw new Error('expected invalid presentation, got valid: true');
  }
  return result;
}

/** VC の結果が `valid: true` の枝であることを確かめて返す。 */
export function assertCredentialValid(
  result: CredentialVerificationResult,
): Extract<CredentialVerificationResult, { valid: true }> {
  if (!result.valid) {
    throw new Error(`expected valid credential, got errors: ${issueCodes(result.errors).join()}`);
  }
  return result;
}

/** VC の結果が `valid: false` の枝であることを確かめて返す。 */
export function assertCredentialInvalid(
  result: CredentialVerificationResult,
): Extract<CredentialVerificationResult, { valid: false }> {
  if (result.valid) {
    throw new Error('expected invalid credential, got valid: true');
  }
  return result;
}
