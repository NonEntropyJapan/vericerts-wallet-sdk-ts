/**
 * Verifier 側 Status List 運用ヘルパー（キャッシュ TTL 評価 / ステータス判定）のユニットテスト。
 *
 * 検証内容:
 * - parseMaxAgeSeconds が max-age を抽出し、no-store / no-cache を 0 にする。
 * - evaluateCacheFreshness が呼び出し側指定の TTL 上限で max-age を切り詰める（SLA 保護）。
 * - Token の exp がキャッシュ失効時刻を前倒しする。
 * - TTL 経過後は fresh=false・残り 0 になる。
 * - evaluateStatusEntry / assertStatusValid が valid / revoked / suspended を判定する。
 * - `valid` とビット値が矛盾する解決器の結果を 3002 で拒否する（DI seam の契約違反を素通りさせない）。
 */

import { describe, expect, it } from 'bun:test';
import type { StatusCheckResult } from '../../credential/sdjwt/status.js';
import { ErrorCodes, VericertsError } from '../../errors.js';
import {
  assertStatusValid,
  DEFAULT_STATUS_CACHE_MAX_TTL_SECONDS,
  evaluateCacheFreshness,
  evaluateStatusEntry,
  parseMaxAgeSeconds,
} from '../status-list-verifier.js';

const FETCHED_AT = 1_700_000_000;

describe('parseMaxAgeSeconds', () => {
  it('max-age を秒数として取り出す', () => {
    expect(parseMaxAgeSeconds('max-age=30')).toBe(30);
    expect(parseMaxAgeSeconds('public, max-age=120, must-revalidate')).toBe(120);
    expect(parseMaxAgeSeconds('MAX-AGE = "45"')).toBe(45);
  });

  it('no-store / no-cache は 0（キャッシュ不可）', () => {
    expect(parseMaxAgeSeconds('no-store')).toBe(0);
    expect(parseMaxAgeSeconds('no-cache, max-age=600')).toBe(0);
  });

  it('未設定 / max-age なしは undefined', () => {
    expect(parseMaxAgeSeconds(undefined)).toBeUndefined();
    expect(parseMaxAgeSeconds(null)).toBeUndefined();
    expect(parseMaxAgeSeconds('public')).toBeUndefined();
  });
});

describe('evaluateCacheFreshness', () => {
  it('max-age 未指定なら TTL 上限をそのまま使う', () => {
    const r = evaluateCacheFreshness({ fetchedAtSeconds: FETCHED_AT, nowSeconds: FETCHED_AT });
    expect(r.effectiveTtlSeconds).toBe(DEFAULT_STATUS_CACHE_MAX_TTL_SECONDS);
    expect(r.fresh).toBe(true);
    expect(r.remainingSeconds).toBe(DEFAULT_STATUS_CACHE_MAX_TTL_SECONDS);
  });

  it('max-age が上限より長ければ上限で切り詰める（失効反映 SLA を守る）', () => {
    const r = evaluateCacheFreshness({
      fetchedAtSeconds: FETCHED_AT,
      nowSeconds: FETCHED_AT,
      maxAgeSeconds: 86_400,
      maxTtlSeconds: 60,
    });
    expect(r.effectiveTtlSeconds).toBe(60);
    expect(r.expiresAtSeconds).toBe(FETCHED_AT + 60);
  });

  it('max-age が上限より短ければ max-age を使う', () => {
    const r = evaluateCacheFreshness({
      fetchedAtSeconds: FETCHED_AT,
      nowSeconds: FETCHED_AT,
      maxAgeSeconds: 10,
      maxTtlSeconds: 60,
    });
    expect(r.effectiveTtlSeconds).toBe(10);
    expect(r.expiresAtSeconds).toBe(FETCHED_AT + 10);
  });

  it('呼び出し側が上限をさらに短くできる', () => {
    const r = evaluateCacheFreshness({
      fetchedAtSeconds: FETCHED_AT,
      nowSeconds: FETCHED_AT,
      maxAgeSeconds: 300,
      maxTtlSeconds: 5,
    });
    expect(r.effectiveTtlSeconds).toBe(5);
  });

  it('Token の exp が TTL より早ければ exp で失効する', () => {
    const r = evaluateCacheFreshness({
      fetchedAtSeconds: FETCHED_AT,
      nowSeconds: FETCHED_AT,
      maxAgeSeconds: 60,
      expSeconds: FETCHED_AT + 20,
    });
    expect(r.expiresAtSeconds).toBe(FETCHED_AT + 20);
    expect(r.remainingSeconds).toBe(20);
  });

  it('TTL 経過後は fresh=false・残り 0（再取得が必要）', () => {
    const r = evaluateCacheFreshness({
      fetchedAtSeconds: FETCHED_AT,
      nowSeconds: FETCHED_AT + 61,
      maxTtlSeconds: 60,
    });
    expect(r.fresh).toBe(false);
    expect(r.remainingSeconds).toBe(0);
  });

  it('失効ちょうどの時刻は fresh=false（境界は再取得側に倒す）', () => {
    const r = evaluateCacheFreshness({
      fetchedAtSeconds: FETCHED_AT,
      nowSeconds: FETCHED_AT + 60,
      maxTtlSeconds: 60,
    });
    expect(r.fresh).toBe(false);
  });

  it('no-store 由来の max-age=0 は常に再取得', () => {
    const r = evaluateCacheFreshness({
      fetchedAtSeconds: FETCHED_AT,
      nowSeconds: FETCHED_AT,
      maxAgeSeconds: parseMaxAgeSeconds('no-store'),
    });
    expect(r.fresh).toBe(false);
    expect(r.effectiveTtlSeconds).toBe(0);
  });

  it('負の時刻 / TTL を 3002 で拒否する', () => {
    expect(() => evaluateCacheFreshness({ fetchedAtSeconds: -1, nowSeconds: FETCHED_AT })).toThrow(
      VericertsError,
    );
    expect(() =>
      evaluateCacheFreshness({
        fetchedAtSeconds: FETCHED_AT,
        nowSeconds: FETCHED_AT,
        maxTtlSeconds: -5,
      }),
    ).toThrow(VericertsError);
  });
});

/** 指定 purpose / value の StatusCheckResult を作る（valid はビット値と整合させる）。 */
function resultOf(purpose: string, value: number): StatusCheckResult {
  return { valid: value === 0, purpose, value };
}

/** 実行が VC_SCHEMA_INVALID（3002）で失敗することを確認する。 */
function expectSchemaInvalid(run: () => unknown): void {
  try {
    run();
    throw new Error('expected throw');
  } catch (e) {
    expect(e).toBeInstanceOf(VericertsError);
    expect((e as VericertsError).code).toBe(ErrorCodes.VC_SCHEMA_INVALID);
  }
}

describe('evaluateStatusEntry', () => {
  it('ビット値 0 は valid', () => {
    expect(evaluateStatusEntry(resultOf('revocation', 0))).toBe('valid');
    expect(evaluateStatusEntry(resultOf('suspension', 0))).toBe('valid');
  });

  it('revocation の非 0 は revoked、suspension の非 0 は suspended', () => {
    expect(evaluateStatusEntry(resultOf('revocation', 1))).toBe('revoked');
    expect(evaluateStatusEntry(resultOf('suspension', 1))).toBe('suspended');
  });

  it('valid=false なのにビット値 0 の解決器結果を 3002 で拒否する', () => {
    expectSchemaInvalid(() =>
      evaluateStatusEntry({ valid: false, purpose: 'revocation', value: 0 }),
    );
  });

  it('valid=true なのにビット値が非 0 の解決器結果を 3002 で拒否する', () => {
    expectSchemaInvalid(() =>
      evaluateStatusEntry({ valid: true, purpose: 'revocation', value: 1 }),
    );
  });
});

describe('assertStatusValid', () => {
  it('有効なら何も投げない', () => {
    expect(() => assertStatusValid(resultOf('revocation', 0))).not.toThrow();
  });

  it('valid とビット値が矛盾する結果を素通りさせず 3002 で拒否する（fail-closed）', () => {
    // 独自解決器が「無効だがビット値 0」を返しても有効と誤判定しない。
    expectSchemaInvalid(() => assertStatusValid({ valid: false, purpose: 'revocation', value: 0 }));
    expectSchemaInvalid(() => assertStatusValid({ valid: true, purpose: 'suspension', value: 1 }));
  });

  it('失効は 3020、一時停止は 3021 を投げる（fail-closed）', () => {
    try {
      assertStatusValid(resultOf('revocation', 1));
      throw new Error('expected throw');
    } catch (e) {
      expect((e as VericertsError).code).toBe(ErrorCodes.VC_REVOKED);
    }
    try {
      assertStatusValid(resultOf('suspension', 1));
      throw new Error('expected throw');
    } catch (e) {
      expect((e as VericertsError).code).toBe(ErrorCodes.VC_SUSPENDED);
    }
  });
});
