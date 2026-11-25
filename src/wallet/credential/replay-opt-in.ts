/**
 * Wallet ファサードの replay 検知 opt-in 判定（`verifySdJwtWith` / `resolvePresentationEnvelope` 共通）。
 *
 * replay 検知（seen-nonces cache による使用 1 回の保証）には `nonceStore`（消費記録の置き場）と
 * `nonceContext`（束縛値と記録のキー空間）の**両方**が要る。「両方指定なし」だけが「replay 検知を
 * 使わない」という明示的な選択で、どちらか一方でも指定した呼び出しは replay 検知を求めている。
 * 片方だけを理由に通常検証へ落とすと、`nonceStore` の配線済みなのに `nonceContext` の組み立て漏れで
 * 使用 1 回の保証が無言で無効になり、同じ KB-JWT / JWT-VP を何度でも受理する（fail-open）。
 */

import { ErrorCodes, VericertsError } from '../../internal/errors.js';

/**
 * `nonceStore` / `nonceContext` が「両方指定」か「両方なし」のどちらかであることを保証する。
 * 両方なしは replay 検知を使わない明示的な選択として呼び出し側が通常検証へ進める。
 *
 * @throws `NONCE_BINDING_MISMATCH`（4012）`nonceStore` だけが指定された（束縛値を決める
 *         `nonceContext` が無い）/ `REPLAY_DETECTED`（4010）`nonceContext` だけが指定された
 *         （消費を記録する `nonceStore` が無い。ガード層の `nonceStore` 欠落と同じコード）。
 */
export function assertReplayInputsComplete(nonceStore: unknown, nonceContext: unknown): void {
  if (nonceContext === undefined && nonceStore !== undefined) {
    throw new VericertsError(ErrorCodes.NONCE_BINDING_MISMATCH);
  }
  if (nonceStore === undefined && nonceContext !== undefined) {
    throw new VericertsError(ErrorCodes.REPLAY_DETECTED);
  }
}
