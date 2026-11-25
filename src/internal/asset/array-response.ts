/**
 * 動的配列を 1 つ返す `eth_call` 応答（`address[]` / `uint256[]`）の、ABI デコード前の件数・長さ検査。
 *
 * ethers の `AbiCoder.decode` は件数に対して二次時間（`uint256[]` 16,000 ワードで約 1.3 秒）で、応答は
 * 信頼境界外の RPC / コントラクト由来。本文サイズ上限（1 MiB）だけでは「少数の要求に大量の要素を返す」
 * 形状を防げないため、呼び出し側が期待する最大件数でデコード**前**に拒否する。
 *
 * 正規のエンコードは `offset(=0x20) || length || 要素 * length` で、末尾に余分なバイトは付かない。
 * 本検査はこの形だけを受理する（戻り値型が単一の動的配列である関数専用）。
 *
 * 拒否は code `1021`（`CHAIN_SUBMIT_FAILED`）、`context.phase = 'array_response_too_large'`。件数・内容は含めない。
 */

import { ErrorCodes, VericertsError } from '../errors.js';

/** 32 バイト = hex 64 文字。 */
const WORD_HEX = 64;
/** 動的配列 1 個の戻り値の先頭 offset ワード（`0x20`）。 */
const ARRAY_OFFSET_WORD = `${'0'.repeat(WORD_HEX - 2)}20`;

/**
 * 動的配列応答の件数が `maxElements` 以内の正規エンコードであることを、デコード前に保証する。
 *
 * @param raw `eth_call` の戻り値（`0x` + hex）。
 * @param maxElements 受理する最大件数（0 以上の整数）。
 * @throws offset が正規でない・長さワードが `maxElements` を超える・総バイト数が
 *         `64 + 32 * length` と一致しない場合（VericertsError、code `1021`）。
 */
export function assertArrayResponseWithin(raw: string, maxElements: number): void {
  const reject = () =>
    new VericertsError(ErrorCodes.CHAIN_SUBMIT_FAILED, {
      context: { phase: 'array_response_too_large' },
    });
  // 最大でも 2 + 64 + 64 + 64 * maxElements 文字。これを超える応答は長さワードを読むまでもなく拒否する。
  if (raw.length > 2 + 2 * WORD_HEX + WORD_HEX * maxElements) throw reject();
  if (raw.length < 2 + 2 * WORD_HEX) throw reject();
  if (raw.slice(2, 2 + WORD_HEX) !== ARRAY_OFFSET_WORD) throw reject();
  const lengthWord = raw.slice(2 + WORD_HEX, 2 + 2 * WORD_HEX);
  if (!/^[0-9a-fA-F]{64}$/.test(lengthWord)) throw reject();
  const length = BigInt(`0x${lengthWord}`);
  if (length > BigInt(maxElements)) throw reject();
  if (raw.length !== 2 + 2 * WORD_HEX + WORD_HEX * Number(length)) throw reject();
}
