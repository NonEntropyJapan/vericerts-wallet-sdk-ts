/**
 * well-known URL 組み立ての末尾スラッシュ除去が線形時間であることの回帰テスト。
 *
 * 旧実装 `replace(/\/+$/, '')` は `/` の長い連続の後ろに文字が続く識別子で O(n²) になり、
 * 取得前の純 CPU 処理だけで SDK 利用側をハングさせた。
 */

import { describe, expect, test } from 'bun:test';
import { fetchInsertedWellKnownJson } from '../index.js';
import { failure, fetchJson, ISSUER, json, stubFetch, WELL_KNOWN_PATH } from './fixtures.js';

const HUGE = 200_000;
const BUDGET_MS = 1_000;
const HOSTILE_SUFFIX = `${'/'.repeat(HUGE)}x`;

describe('well-known URL 組み立て（長い `/` 連続）', () => {
  test('末尾連結形 `fetchWellKnownJson` は線形時間で URL を組み立てる', async () => {
    const stub = stubFetch(() => json({}));
    const start = performance.now();
    await fetchJson(`${ISSUER}/${HOSTILE_SUFFIX}`, stub.fetchImpl);
    expect(performance.now() - start).toBeLessThan(BUDGET_MS);
    expect(stub.urls).toEqual([`${ISSUER}/${HOSTILE_SUFFIX}${WELL_KNOWN_PATH}`]);
  });

  test('挿入形 `fetchInsertedWellKnownJson` は線形時間で URL を組み立てる', async () => {
    const stub = stubFetch(() => json({}));
    const start = performance.now();
    await fetchInsertedWellKnownJson(
      `${ISSUER}/${HOSTILE_SUFFIX}`,
      WELL_KNOWN_PATH,
      stub.fetchImpl,
      failure,
    );
    expect(performance.now() - start).toBeLessThan(BUDGET_MS);
    expect(stub.urls).toEqual([`${ISSUER}${WELL_KNOWN_PATH}/${HOSTILE_SUFFIX}`]);
  });
});
