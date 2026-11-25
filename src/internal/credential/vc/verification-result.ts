/**
 * 高レベル Verifier API `verifyCredential` の戻り値型。
 *
 * 2 層構成のうち**高レベル側**。低レベル primitive（`verifyCredential`
 * プリミティブ / ファサードの `verifyCredentialStrict`）は fail-closed で例外を投げ、成功時のみ
 * `VerifiedCredential` を返す。本型はその上に載る判別共用体で、失敗を例外ではなく
 * `valid: false` + `errors` として返す。
 *
 * `valid` で判別すること。`valid: true` の枝にしか `data` は無く、`valid: false` の枝には
 * `data` が存在しない（未検証の VC を「検証済み」として読み出せないようにするため）。
 */

import type { VerificationIssue } from '../verification-issue.js';
import type { VerifiedCredential } from './verify.js';

/** `verifyCredential`（高レベル）の結果。`valid` で判別する判別共用体。 */
export type CredentialVerificationResult =
  | {
      /** 署名・時刻・（指定時）FC-11 をすべて通った。 */
      readonly valid: true;
      /** デコード済みヘッダ・ペイロード（primitive と同じもの）。 */
      readonly data: VerifiedCredential;
      /** 拒否には至らなかった注意事項。現時点では常に空配列。 */
      readonly warnings: readonly VerificationIssue[];
    }
  | {
      /** いずれかの検査で不成立。`data` は返さない。 */
      readonly valid: false;
      /** 失敗理由（最低 1 件）。 */
      readonly errors: readonly VerificationIssue[];
    };
