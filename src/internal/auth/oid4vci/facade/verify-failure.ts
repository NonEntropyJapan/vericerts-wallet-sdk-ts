/**
 * 受領した VC の検証失敗を、元のエラーコードを潰さずに扱うための判定。
 *
 * 受領後の検証（既定検証・明示フック）は、署名が合わない（`3010`）以外にも `3002`（構造不正・
 * envelope↔body 不整合）/ `3024`（期限切れ）/ `3025`（有効化前）/ `5012`（鍵無効化）などで失敗する。
 * これらを一律 `3010` へ畳むと、呼び出し側は本当の原因を知れず、署名不一致と取り違える。
 *
 * - `3010` 以外の `VericertsError` は**元のコードのまま**投げ直す（本関数が返す）。
 * - `3010` の `VericertsError` と、`VericertsError` でない例外（暗号ライブラリ由来・フック内の
 *   任意の throw）は `undefined` を返す。呼び出し側が従来どおり `3010`
 *   （`received_credential_signature_invalid`）へ正規化する。VC 本文・署名を載せ得る素の例外を
 *   伝播させないため、後者は元の例外を返さない。
 */

import { ErrorCodes, VericertsError } from '../../../errors.js';

/**
 * @param failure 検証処理が投げた値。
 * @returns 元のコードのまま投げ直すべき `VericertsError`。`3010` へ正規化すべきなら `undefined`。
 */
export function preservedVerifyFailure(failure: unknown): VericertsError | undefined {
  if (failure instanceof VericertsError && failure.code !== ErrorCodes.SIG_INVALID) {
    return failure;
  }
  return undefined;
}
