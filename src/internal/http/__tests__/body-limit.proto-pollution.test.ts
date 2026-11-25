/**
 * `readBodyWithinLimit` / `isAllowedContentType` 等のオプション読み出しは `Object.prototype` を辿らない。
 *
 * `options?.maxBytes` / `options?.onBytes` が鎖読みだと、省略した呼び出しが汚染値の上限・計上フックを拾う
 * （上限を緩められる / 総量予算の計上を横取りされる）。
 */

import { describe, expect, test } from 'bun:test';
import { withPollutedPrototypeAsync } from '../../__tests__/prototype-pollution.fixtures.js';
import { MAX_DOCUMENT_BYTES, readBodyWithinLimit } from '../body-limit.js';

function bodylessResponse(text: string): Response {
  return { body: undefined, text: () => Promise.resolve(text) } as unknown as Response;
}

describe('body-limit のオプション読み出し', () => {
  test.each([
    ['maxBytes を緩める値', { maxBytes: MAX_DOCUMENT_BYTES * 8 }],
    ['maxBytes を 0 にする値', { maxBytes: 0 }],
  ])('汚染された %s は採用されず、既定の上限のまま', async (_name, polluted) => {
    const withinLimit = 'a'.repeat(1024);
    const oversized = 'a'.repeat(MAX_DOCUMENT_BYTES + 1);
    await withPollutedPrototypeAsync(polluted, async () => {
      expect(await readBodyWithinLimit(bodylessResponse(withinLimit))).toBe(withinLimit);
      expect(await readBodyWithinLimit(bodylessResponse(oversized))).toBeUndefined();
    });
  });

  test('汚染された onBytes は呼ばれない', async () => {
    const seen: number[] = [];
    await withPollutedPrototypeAsync({ onBytes: (n: number) => seen.push(n) }, () =>
      readBodyWithinLimit(bodylessResponse('{}'), {}),
    );
    expect(seen).toEqual([]);
  });

  test('own で渡した onBytes / maxBytes は従来どおり効く（正常系）', async () => {
    const seen: number[] = [];
    expect(
      await readBodyWithinLimit(bodylessResponse('abcd'), { onBytes: (n) => seen.push(n) }),
    ).toBe('abcd');
    expect(seen).toEqual([4]);
    expect(await readBodyWithinLimit(bodylessResponse('abcde'), { maxBytes: 4 })).toBeUndefined();
  });
});
