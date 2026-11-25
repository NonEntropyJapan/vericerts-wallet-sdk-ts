/**
 * `*_duration_seconds` 系メトリクスの**単位**（秒 / ミリ秒）を実時間に依存せず確かめるヘルパー。
 *
 * ## なぜ実測 ms を上限にするのか
 *
 * duration 系の単位は秒（名前の `_seconds` サフィックス）。
 * これを「記録値が 1 未満であること」で確かめていた断言は、**単位の検査のつもりで実時間の
 * 絶対値を見ていた**ため、負荷の高いマシンで意図と無関係に落ちた（`lefthook.yml` の pre-push は
 * `sdk-test` と `extension-test`（vitest・207 ファイル）を含む 4 コマンドを `parallel: true` で
 * 同時に走らせる。競合下では `wallet.encrypt` の KDF が実測 1.67 秒に達し、`< 1` が破れた）。
 * フックが偽陰性で赤くなることは `--no-verify` の誘因にもなる。
 *
 * 上限を**外側で測った実測 ms の 1/1000** に置くと、この偽陰性が原理的に消える。
 *
 * - 計装区間（記録側）は必ず計測区間（テスト側）に含まれ、どちらも同じ `Date.now()` の整数 ms から
 *   作られる。したがって秒で載っていれば記録値は必ず `elapsedMs / 1000` 以下になる。
 * - ミリ秒のまま載せていれば記録値は実測 ms と同じ桁（= 上限の約 1000 倍）になり、確実に落ちる。
 * - 負荷でマシンが遅くなると実測 ms も上限も同じだけ伸びるので、閾値の調整が要らない。
 *
 * ## 同種の断言についての注記
 *
 * `toBeLessThan` で実時間を見る断言は SDK 内に他にもあるが（`keymanager/__tests__/hd/hd.derive.test.ts`
 * の `< 50`、`mnemonic.generate.test.ts` の `< 100`、`credential/json-schema/__tests__/` の ReDoS
 * ガード、`gdpr/__tests__/deletion/` の件数スケール検査）、いずれも**時間そのものが断言の目的**
 * （non-functional 性能要件・破滅的バックトラックの検知）であり、本モジュールが置き換える
 * 「単位の検査を実時間で代用していた断言」とは別種である。置き換えの対象にしない。
 */

import { expect } from 'bun:test';

/**
 * `action` を実行し、その実時間（ミリ秒）を返す。
 *
 * 記録側と同じ `Date.now()` で測る（`performance.now()` と混ぜると起点の違う 2 つの時計を
 * 比較することになり、「内側は外側に含まれる」という上限の根拠が崩れる）。
 */
export async function timed(action: () => Promise<unknown>): Promise<number> {
  const startedAt = Date.now();
  await action();
  return Date.now() - startedAt;
}

/**
 * ヒストグラムの `sum` が**秒**で載っていることを、実測 ms を上限として確かめる。
 *
 * @param recordedSum 記録された合計値（系列が無ければ `undefined`。その場合も失敗させる）。
 * @param elapsedMs {@link timed} が返した、計装区間を含む実測時間（ミリ秒）。
 */
export function expectRecordedInSeconds(recordedSum: number | undefined, elapsedMs: number): void {
  expect(recordedSum).toBeGreaterThanOrEqual(0);
  expect(recordedSum).toBeLessThanOrEqual(elapsedMs / 1000);
}
