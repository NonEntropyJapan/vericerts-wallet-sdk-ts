/**
 * Entity Configuration 取得で「読まない本文」を解放することの回帰テスト。
 *
 * 背景:
 * 未消費の応答本文は undici でもブラウザでも接続とバッファ済みバイトを GC まで保持する。
 * この経路は本文を読む前に throw する出口を 3 つ持ち（非 2xx / Content-Type 不正 /
 * 宣言サイズ超過）、いずれも `finally` の `discardBody` が無ければソケットを掴んだまま残る。
 *
 * `entity-configuration.ts` は FO-6 の唯一の駆動元（`fail-open/entity-configuration-fail-open.ts`）
 * であり、その失敗経路こそ攻撃者が支配する entity に繰り返し踏ませることが想定されている。
 * 双子の `subordinate.ts` は 既に解放しており、ここだけが取り残されていた。
 *
 * 同型の取りこぼしがモジュール横断で再発しないことは
 * `internal/__tests__/repo/response-body-release.test.ts` が機械的に固定する。本ファイルは
 * この経路で実際に `cancel()` まで届くこと（配線）を見る。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../../../errors.js';
import { resolveEntityConfiguration } from '../../entity-configuration.js';
import { nowFn } from '../federation-fixtures.js';

const ENTITY_ID = 'https://leaf.example.eu';

/** `cancel()` されたかを記録する本文を持つ応答を返す fetch モック。 */
function cancelRecordingFetch(init: ResponseInit): {
  fetchFn: typeof fetch;
  cancelled: () => boolean;
} {
  let cancelled = false;
  const fetchFn = (async (_input: string | URL): Promise<Response> => {
    const body = new ReadableStream<Uint8Array>({
      pull(controller) {
        controller.enqueue(new TextEncoder().encode('x'));
        controller.close();
      },
      cancel() {
        cancelled = true;
      },
    });
    return new Response(body, init);
  }) as typeof fetch;
  return { fetchFn, cancelled: () => cancelled };
}

/** 取得が 5011 で失敗し、かつ応答本文が解放されていることを検証する。 */
async function expectFetchFailedAndBodyReleased(init: ResponseInit): Promise<void> {
  const { fetchFn, cancelled } = cancelRecordingFetch(init);
  let caught: unknown;
  try {
    await resolveEntityConfiguration(ENTITY_ID, { fetchFn, now: nowFn });
  } catch (error) {
    caught = error;
  }
  expect(caught).toBeInstanceOf(VericertsError);
  expect((caught as VericertsError).code).toBe(ErrorCodes.FEDERATION_FETCH_FAILED);
  // `discardBody` は `cancel()` の完了を待たない（元のエラーを覆さないため）ので 1 tick 譲る。
  await Promise.resolve();
  expect(cancelled()).toBe(true);
}

describe('resolveEntityConfiguration - 読まない本文の解放', () => {
  it('非 2xx で throw する経路は本文を解放する', async () => {
    await expectFetchFailedAndBodyReleased({ status: 404 });
  });

  it('Content-Type 不正で throw する経路は本文を解放する', async () => {
    await expectFetchFailedAndBodyReleased({
      status: 200,
      headers: { 'content-type': 'text/html' },
    });
  });

  it('宣言サイズ超過で throw する経路は本文を解放する', async () => {
    await expectFetchFailedAndBodyReleased({
      status: 200,
      // `MAX_DOCUMENT_BYTES`（1 MiB）+ 1 を自己申告させ、本文を読む前に落とす。
      headers: { 'content-type': 'application/jwt', 'content-length': '1048577' },
    });
  });
});
