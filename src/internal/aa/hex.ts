/**
 * aa モジュールの JSON-RPC レスポンス hex 変換ヘルパー。
 *
 * Bundler（bundler.ts）と Paymaster（paymaster.ts）は JSON-RPC が返す hex 文字列を bigint へ
 * 変換する同一の処理を各々が持っていたため、重複を除くために本モジュールへ切り出した。
 * 型のみを提供する types.ts とは役割が異なるため、実行時ロジックは本ファイルに置く。
 *
 * セキュリティ上の注意:
 * - 不正値の内容を例外 message / context / cause に伝播させない。
 *   レスポンス形状失敗は VericertsError（code `1021`、retriable）に正規化する。
 */

import { ErrorCodes, VericertsError } from '../errors.js';

/** hex 文字列を bigint へ変換する。不正値は 1021 に正規化する。 */
export function fromHex(value: unknown): bigint {
  if (typeof value !== 'string' || !value.startsWith('0x')) {
    throw new VericertsError(ErrorCodes.CHAIN_SUBMIT_FAILED);
  }
  try {
    return BigInt(value);
  } catch {
    throw new VericertsError(ErrorCodes.CHAIN_SUBMIT_FAILED);
  }
}
