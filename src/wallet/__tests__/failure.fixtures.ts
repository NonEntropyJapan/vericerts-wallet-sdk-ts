/**
 * `VericertsError` の失敗面をアサートするための共通ヘルパー。
 *
 * Wallet 層のテストは「どの `code` と `context.reason` で倒れるか」を固定することが多い。
 * 各テストファイルへ同じ関数を書き写すと、片方だけ「投げなければ失敗させる」を落とす・
 * `VericertsError` 以外の例外を素通しするといった**緩い版**が生まれ、fail-closed を確かめる
 * はずのテストが穴になる。1 本に集約してその差を作れなくする。
 */

import { expect } from 'bun:test';
import { VericertsError } from '../../internal/errors.js';

/**
 * `run` が投げた `VericertsError` の `code` と `context.reason` を取り出す。
 *
 * 投げなかった場合は**テストを失敗させる**（戻り値を返さない）。`VericertsError` 以外を投げた
 * 場合も `expect` が失敗する — 別種の例外を「期待どおりの失敗」として通さないためである。
 *
 * @param run 失敗するはずの処理。
 * @returns 投げられた `VericertsError` の `code` と `context.reason`。
 */
export async function failureOf(
  run: () => Promise<unknown>,
): Promise<{ code: string; reason: unknown }> {
  try {
    await run();
  } catch (e) {
    expect(e).toBeInstanceOf(VericertsError);
    const error = e as VericertsError;
    return { code: error.code, reason: error.context?.reason };
  }
  throw new Error('should throw');
}
