/**
 * 公開バレルへの `@experimental` ランタイム警告配線の回帰テスト。
 *
 * 機構そのもの（`internal/experimental-warning.ts`）は
 * `src/internal/__tests__/experimental-warning.test.ts` が固定する。本テストは**公開面**、
 * つまりサブパスバレル `src/exports/experimental.ts`から import した名前が
 * 実際に警告を出すこと（1 回/プロセス・API 名ごと）と、非 `@experimental` API（ドメインバレル
 * `src/exports/auth.ts`）が警告を出さないこと・`Proxy` ラップがクラスの `instanceof` を壊さないことを固定する。
 */

import { afterEach, beforeEach, describe, expect, spyOn, test } from 'bun:test';
import {
  resetExperimentalWarnings,
  SUPPRESS_EXPERIMENTAL_WARNINGS_ENV,
} from '../../internal/experimental-warning.js';
import { generateNonce } from '../auth.js';
import {
  ChainVerificationCache,
  contextKeyFrom,
  entryKeyFrom,
  receiveCredential,
} from '../experimental.js';

describe('experimental サブパスバレルの @experimental ランタイム警告', () => {
  let warn: ReturnType<typeof spyOn<Console, 'warn'>>;

  beforeEach(() => {
    resetExperimentalWarnings();
    delete process.env[SUPPRESS_EXPERIMENTAL_WARNINGS_ENV];
    warn = spyOn(console, 'warn').mockImplementation(() => {});
  });

  afterEach(() => {
    warn.mockRestore();
    resetExperimentalWarnings();
  });

  test('同じ公開 API を 2 回呼んでも警告は 1 回だけ', () => {
    expect(contextKeyFrom('oid4vp', 'https://rp.example')).toBe('oid4vp:https%3A%2F%2Frp.example');
    expect(contextKeyFrom('oid4vp', 'https://rp.example')).toBe('oid4vp:https%3A%2F%2Frp.example');

    expect(warn).toHaveBeenCalledTimes(1);
    const message = String(warn.mock.calls[0]?.[0]);
    expect(message).toContain('`contextKeyFrom` is @experimental');
    expect(message).toContain('may change in a minor release');
    expect(message).not.toMatch(/\.md\b/);
  });

  test('別の公開 API はそれぞれ 1 回ずつ警告する（合計 2 回）', () => {
    contextKeyFrom('oid4vp', 'x');
    contextKeyFrom('oid4vp', 'x');
    entryKeyFrom('n', 'oid4vp', 'x');
    entryKeyFrom('n', 'oid4vp', 'x');

    expect(warn).toHaveBeenCalledTimes(2);
    const messages = warn.mock.calls.map((call) => String(call[0]));
    expect(messages.some((m) => m.includes('`contextKeyFrom`'))).toBe(true);
    expect(messages.some((m) => m.includes('`entryKeyFrom`'))).toBe(true);
  });

  test('ラップしてもクラスの instanceof は壊れない', () => {
    const cache = new ChainVerificationCache();
    // 型としても解決できること（`export type` を落とすと利用者側でここが壊れる）。
    const typed: ChainVerificationCache = cache;

    expect(typed).toBeInstanceOf(ChainVerificationCache);
    expect(cache.get('missing', Date.now())).toBeUndefined();
    expect(warn).toHaveBeenCalledTimes(1);
    expect(String(warn.mock.calls[0]?.[0])).toContain('`ChainVerificationCache` is @experimental');
  });

  test('非 @experimental の公開 API は警告しない', () => {
    expect(typeof generateNonce()).toBe('string');

    expect(warn).not.toHaveBeenCalled();
  });

  test('@deprecated へ移行した receiveCredential は @experimental ではなく @deprecated として警告する', () => {
    // 警告は `Proxy` の `apply` トラップで呼び出し時点に同期的に出るため、Offer URI が不正で
    // 実際の受領が失敗しても警告の検証には影響しない（reject は無視する）。
    void receiveCredential('not-a-valid-offer-uri', {} as never).catch(() => {});

    expect(warn).toHaveBeenCalledTimes(1);
    const message = String(warn.mock.calls[0]?.[0]);
    expect(message).toContain('`receiveCredential` is @deprecated');
    expect(message).toContain('Wallet.receiveCredential');
    expect(message).not.toMatch(/\.md\b/);
  });
});
