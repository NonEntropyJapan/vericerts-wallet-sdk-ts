/**
 * SD-JWT VC の `status`（Token Status List 参照）解決インターフェース。
 *
 * IETF draft-ietf-oauth-status-list 準拠。
 *
 * 本モジュールは `status` クレームの**構造保持と参照解決のインターフェース**までを担う。
 * 実際の失効ビット評価（Status List Token の取得・展開・ビット読取り）は issuer ドメインの
 * 責務であり、ここでは解決器（`StatusListResolver`）を DI する seam と、status クレーム未設定時の
 * `TOKEN_STATUS_LIST_UNSUPPORTED`（3018）を提供する。
 *
 * セキュリティ上の注意:
 * - 例外メッセージや `context` に URL・インデックス・JWT を含めない。
 */

import { ErrorCodes, VericertsError } from '../../errors.js';
import type { FailSafeWarning } from '../../failsafe-policy/index.js';
import type { StatusReference } from './sdjwt.js';

/** Status List 参照のステータス評価結果。 */
export interface StatusCheckResult {
  /** ステータスチェックを通過したか（ビット値が 0）。 */
  readonly valid: boolean;
  /** ステータスの用途（`revocation` / `suspension`）。 */
  readonly purpose: string;
  /** 読み取ったビット値。 */
  readonly value: number;
  /**
   * Fail-open で通過した場合の警告。
   *
   * ステータスを実際に読み取れた通常経路では設定されない。設定されている場合は「失効状態を確認
   * できていないまま通過した」ことを意味するため、UI で警告を提示する必要がある。
   */
  readonly warnings?: readonly FailSafeWarning[];
}

/**
 * Token Status List 参照を評価する解決器。
 *
 * 実装は `idx` / `uri` から Status List Token を取得・展開してビット値を返す（issuer ドメイン）。
 * credential ドメインでは構造保持と DI のみを担うため、本インターフェースを介して評価を委譲する。
 */
export interface StatusListResolver {
  /**
   * Status List 参照を評価してステータスを返す。
   * @param ref SD-JWT VC の `status` クレーム。
   * @returns ステータス評価結果。
   */
  resolve(ref: StatusReference): Promise<StatusCheckResult>;
}

/**
 * SD-JWT VC の `status` 参照を解決する。
 *
 * `status` クレームが未設定（Token Status List 非対応の VC）の場合は
 * `TOKEN_STATUS_LIST_UNSUPPORTED`（3018）を投げる。設定済みなら DI された `resolver` に
 * 評価を委譲する。
 *
 * @param status SD-JWT VC の `status` クレーム（`verifySdJwt` の結果由来）。
 * @param resolver Status List 評価器（issuer ドメインが実装を供給する）。
 * @returns ステータス評価結果。
 * @throws status クレーム未設定の場合（VericertsError、code `3018`）。
 */
export function resolveStatus(
  status: StatusReference | undefined,
  resolver: StatusListResolver,
): Promise<StatusCheckResult> {
  if (status === undefined) {
    throw new VericertsError(ErrorCodes.TOKEN_STATUS_LIST_UNSUPPORTED);
  }
  return resolver.resolve(status);
}
