import { afterEach, beforeEach, describe, expect, spyOn, test } from 'bun:test';
import {
  markDeprecated,
  markExperimental,
  resetExperimentalWarnings,
  SUPPRESS_EXPERIMENTAL_WARNINGS_ENV,
  warnDeprecatedOnce,
  warnExperimentalOnce,
} from '../experimental-warning.js';

/**
 * `@experimental` ランタイム警告の回帰テスト。
 *
 * 規定は「ランタイムで警告ログを **1 回/プロセス** 出す」。呼び出しごとに出さないこと、
 * および API ごとに独立して 1 回出ることの両方を固定する。
 */
describe('experimental runtime warning', () => {
  let warn: ReturnType<typeof spyOn<Console, 'warn'>>;

  beforeEach(() => {
    resetExperimentalWarnings();
    delete process.env[SUPPRESS_EXPERIMENTAL_WARNINGS_ENV];
    warn = spyOn(console, 'warn').mockImplementation(() => {});
  });

  afterEach(() => {
    warn.mockRestore();
    resetExperimentalWarnings();
    delete process.env[SUPPRESS_EXPERIMENTAL_WARNINGS_ENV];
  });

  test('warns once per process for the same API even when called repeatedly', () => {
    const wrapped = markExperimental('sampleApi', (n: number): number => n + 1);

    expect(wrapped(1)).toBe(2);
    expect(wrapped(2)).toBe(3);
    expect(wrapped(3)).toBe(4);

    expect(warn).toHaveBeenCalledTimes(1);
    expect(String(warn.mock.calls[0]?.[0])).toContain('`sampleApi` is @experimental');
  });

  test('warns separately for each distinct API', () => {
    const first = markExperimental('firstApi', () => 'a');
    const second = markExperimental('secondApi', () => 'b');

    first();
    first();
    second();
    second();

    expect(warn).toHaveBeenCalledTimes(2);
    const messages = warn.mock.calls.map((call) => String(call[0]));
    expect(messages.some((m) => m.includes('`firstApi`'))).toBe(true);
    expect(messages.some((m) => m.includes('`secondApi`'))).toBe(true);
  });

  test('warns once for a class regardless of how many instances are constructed', () => {
    class Sample {
      constructor(readonly value: number) {}
    }
    const Wrapped = markExperimental('SampleClass', Sample);

    const a = new Wrapped(1);
    const b = new Wrapped(2);

    expect(a.value).toBe(1);
    expect(b.value).toBe(2);
    // Proxy でラップするため prototype 鎖が保たれ instanceof が壊れない。
    expect(a instanceof Sample).toBe(true);
    expect(a instanceof Wrapped).toBe(true);
    expect(warn).toHaveBeenCalledTimes(1);
  });

  test('warnExperimentalOnce is idempotent for the same name', () => {
    warnExperimentalOnce('directApi');
    warnExperimentalOnce('directApi');
    warnExperimentalOnce('directApi');

    expect(warn).toHaveBeenCalledTimes(1);
  });

  test('suppression env var silences the warning but keeps the API working', () => {
    process.env[SUPPRESS_EXPERIMENTAL_WARNINGS_ENV] = '1';
    const wrapped = markExperimental('silencedApi', () => 42);

    expect(wrapped()).toBe(42);
    expect(warn).not.toHaveBeenCalled();
  });

  test('preserves function identity metadata through the proxy', () => {
    function namedApi(_a: number, _b: string): void {}
    const wrapped = markExperimental('namedApi', namedApi);

    expect(wrapped.name).toBe('namedApi');
    expect(wrapped.length).toBe(2);
  });

  test('propagates thrown errors from the wrapped implementation', () => {
    const wrapped = markExperimental('throwingApi', () => {
      throw new Error('boom');
    });

    expect(() => wrapped()).toThrow('boom');
    expect(() => wrapped()).toThrow('boom');
    expect(warn).toHaveBeenCalledTimes(1);
  });
});

/**
 * `@deprecated` ランタイム警告の回帰テスト。
 *
 * `markDeprecated` は `markExperimental` と同じ `warnedApis` の Set を共有するため、1 回/プロセス・
 * API 名ごとという不変条件は共通の `warnOnce` 実装で保たれる。
 */
describe('deprecated runtime warning', () => {
  let warn: ReturnType<typeof spyOn<Console, 'warn'>>;

  beforeEach(() => {
    resetExperimentalWarnings();
    delete process.env[SUPPRESS_EXPERIMENTAL_WARNINGS_ENV];
    warn = spyOn(console, 'warn').mockImplementation(() => {});
  });

  afterEach(() => {
    warn.mockRestore();
    resetExperimentalWarnings();
    delete process.env[SUPPRESS_EXPERIMENTAL_WARNINGS_ENV];
  });

  test('warns once per process for the same API even when called repeatedly, mentioning the replacement', () => {
    const wrapped = markDeprecated(
      'sampleDeprecatedApi',
      (n: number): number => n + 1,
      'Use `newApi` instead.',
    );

    expect(wrapped(1)).toBe(2);
    expect(wrapped(2)).toBe(3);

    expect(warn).toHaveBeenCalledTimes(1);
    const message = String(warn.mock.calls[0]?.[0]);
    expect(message).toContain('`sampleDeprecatedApi` is @deprecated');
    expect(message).toContain('Use `newApi` instead.');
  });

  test('warnDeprecatedOnce is idempotent for the same name', () => {
    warnDeprecatedOnce('directDeprecatedApi', 'Use `newApi` instead.');
    warnDeprecatedOnce('directDeprecatedApi', 'Use `newApi` instead.');

    expect(warn).toHaveBeenCalledTimes(1);
  });

  test('suppression env var silences the warning but keeps the API working', () => {
    process.env[SUPPRESS_EXPERIMENTAL_WARNINGS_ENV] = '1';
    const wrapped = markDeprecated('silencedDeprecatedApi', () => 42, 'Use `newApi` instead.');

    expect(wrapped()).toBe(42);
    expect(warn).not.toHaveBeenCalled();
  });

  test('preserves function identity metadata through the proxy', () => {
    function namedApi(_a: number, _b: string): void {}
    const wrapped = markDeprecated('namedDeprecatedApi', namedApi, 'Use `newApi` instead.');

    expect(wrapped.name).toBe('namedApi');
    expect(wrapped.length).toBe(2);
  });
});
