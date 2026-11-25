/**
 * {@link readBodyWithinLimit} の**本文の取り出し方**の規律。
 *
 * 上限そのもの（1 MiB 超過を `undefined` に倒す）は各取得経路のテストが押さえているので、ここで
 * 固定するのは「`body` を持たない応答をどう読むか」だけである。
 *
 * **なぜ `undefined` を明示的に押さえるのか。** 実 `fetch` の `Response` は常に `body` を持つが、
 * 本関数は `Response` を模したテストダブルも読めることを docblock で約束している。ところが
 * 「無い」ことの表し方は `body: null` と `body` プロパティ自体の不在（`undefined`）の 2 通りあり、
 * `null` だけを見る実装は後者で `getReader` の参照が TypeError になった。呼び出し側は本文読み出しの
 * 例外を軒並み「取得失敗」へ正規化する（`did-web-fetch.ts` なら `DID_NOT_FOUND`）ので、この取りこぼしは
 * did:web の DID Document が取得できたのに解決失敗となり、失効評価が `unknown` に倒れる形で現れた。
 */

import { describe, expect, test } from 'bun:test';
import { discardBody, MAX_DOCUMENT_BYTES, readBodyWithinLimit } from '../body-limit.js';

/** `body` の表現だけを差し替えた `Response` 風のテストダブル。 */
function bodylessResponse(text: string, body: null | undefined): Response {
  return { body, text: () => Promise.resolve(text) } as unknown as Response;
}

describe('readBodyWithinLimit', () => {
  test.each([
    ['body が null', null],
    ['body プロパティが無い（undefined）', undefined],
  ] as ReadonlyArray<
    readonly [string, null | undefined]
  >)('%s 応答は text() で読み切る', async (_label, body) => {
    expect(await readBodyWithinLimit(bodylessResponse('{"ok":true}', body))).toBe('{"ok":true}');
  });

  test('body を持たない応答でも上限超過は undefined に倒す', async () => {
    const oversized = 'a'.repeat(MAX_DOCUMENT_BYTES + 1);
    expect(await readBodyWithinLimit(bodylessResponse(oversized, undefined))).toBeUndefined();
  });

  test('arrayBuffer() を持つ応答は text() を呼ばずバイト長で判定する', async () => {
    // 公開 DI 面（`FetchLike`）は `body` を型で要求しないので、ホストアプリの実装が素のオブジェクト
    // としてここに来る。その経路でも上限超過を**文字列化の前に**落とすことを押さえる。
    const oversized = new Uint8Array(MAX_DOCUMENT_BYTES + 1);
    let textCalls = 0;
    const response = {
      arrayBuffer: () => Promise.resolve(oversized.buffer),
      text: () => {
        textCalls += 1;
        return Promise.resolve('');
      },
    } as unknown as Response;
    expect(await readBodyWithinLimit(response)).toBeUndefined();
    expect(textCalls).toBe(0);
  });

  test('上限超過の cancel() が reject しても undefined を返す', async () => {
    // `await reader.cancel()` だと reject が呼び出し側の catch へ落ち、軒並みトランスポート失敗へ
    // 正規化される。上限超過を検出した当の経路で超過という情報を失わないことを押さえる。
    const response = {
      body: new ReadableStream<Uint8Array>({
        pull(controller) {
          controller.enqueue(new Uint8Array(MAX_DOCUMENT_BYTES + 1));
        },
        cancel: () => Promise.reject(new Error('cancel failed')),
      }),
    } as unknown as Response;
    expect(await readBodyWithinLimit(response)).toBeUndefined();
  });
});

/** `cancel()` の呼び出し回数を記録する `ReadableStream` を持つ応答ダブル。 */
function cancelRecordingResponse(): { response: Response; cancelCount: () => number } {
  let cancelCount = 0;
  const body = new ReadableStream<Uint8Array>({
    pull(controller) {
      controller.enqueue(new TextEncoder().encode('{"ok":true}'));
      controller.close();
    },
    cancel() {
      cancelCount += 1;
    },
  });
  return { response: { body } as unknown as Response, cancelCount: () => cancelCount };
}

describe('discardBody', () => {
  test('読まずに捨てる本文は cancel() で解放する', async () => {
    const { response, cancelCount } = cancelRecordingResponse();
    discardBody(response);
    await Promise.resolve();
    expect(cancelCount()).toBe(1);
  });

  test('読了済みの本文に対しては何も起きない（二重解放しない）', async () => {
    const { response, cancelCount } = cancelRecordingResponse();
    expect(await readBodyWithinLimit(response)).toBe('{"ok":true}');
    discardBody(response);
    await Promise.resolve();
    expect(cancelCount()).toBe(0);
  });

  test('読み出し中（locked）の本文には触らない', async () => {
    const { response, cancelCount } = cancelRecordingResponse();
    const reader = (response.body as ReadableStream<Uint8Array>).getReader();
    discardBody(response);
    await Promise.resolve();
    expect(cancelCount()).toBe(0);
    await reader.cancel();
  });

  test.each([
    ['応答が undefined', undefined],
    ['body が null', { body: null } as unknown as Response],
    ['body プロパティが無い', {} as unknown as Response],
  ] as ReadonlyArray<
    readonly [string, Response | undefined]
  >)('%s でも例外にしない', (_label, response) => {
    expect(() => discardBody(response)).not.toThrow();
  });
});
