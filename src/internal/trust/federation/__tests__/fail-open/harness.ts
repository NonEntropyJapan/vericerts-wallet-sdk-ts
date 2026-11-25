/**
 * FO-6（Entity Configuration 到達不能時の stale キャッシュ通過）テストの共有ヘルパ。
 *
 * 可変時計・途中でオフラインに切り替えられる fetch・キャッシュ・監査シンク・同意コールバックを
 * 1 つにまとめる。FO-6 は「一度取得に成功してキャッシュを持っている」状態が前提のため、
 * どのテストも「成功 → 時計を進めて TTL 切れ → オフライン」という同じ筋書きを踏む。
 *
 * テストケースは含まない（Linterly の 1 ファイル 300 行上限に収めるための分離）。
 */

import { expect } from 'bun:test';
import { type ErrorCode, VericertsError } from '../../../../errors.js';
import type {
  FailSafeAuditRecord,
  FailSafeDecision,
  FailSafeWarning,
} from '../../../../failsafe-policy/index.js';
import { MAX_DOCUMENT_BYTES } from '../../../../http/body-limit.js';
import { createFederationStatementCache } from '../../cache/statement-cache.js';
import type { ResolveEntityConfigurationDeps } from '../../entity-configuration.js';
import { makeFetchMock, NOW_SECONDS } from '../federation-fixtures.js';

/** FO-6 の監査イベント名。 */
export const FO6_WARNING: FailSafeWarning = {
  policyEvent: 'FO-6',
  auditEvent: 'federation_fetch_failed_cache_ok',
};

/**
 * キャッシュ TTL 上限（600 秒）を確実に超える前進量。
 *
 * これだけ進めてもフィクスチャの Statement は `exp`（NOW + 3600）内に留まるため、stale な JWT の
 * 再検証は成功する。すなわち「TTL 切れだが署名・有効期間は成立している」状態を作れる。
 */
export const STALE_AFTER_SECONDS = 700;

/** FO-6 テスト用の可変環境。 */
export interface FailOpenHarness {
  /** 記録された監査レコード。 */
  readonly records: FailSafeAuditRecord[];
  /** 同意コールバックに渡された判定。 */
  readonly consents: FailSafeDecision[];
  /** 注入用のキャッシュ・fetch・時計（テストごとに fail-safe 系の依存を足して使う）。 */
  readonly base: ResolveEntityConfigurationDeps;
  /** 時計を進める（秒）。 */
  advance(seconds: number): void;
  /**
   * 以降の取得を 503 にする。
   *
   * @param match 503 を返す URL の条件。省略時はすべての取得を失敗させる。
   */
  goOffline(match?: (url: string) => boolean): void;
  /**
   * 以降の取得を「200 だが本文が 1 MiB 超」にする（`readBodyWithinLimit` が打ち切る応答）。
   *
   * @param match 上限超過を返す URL の条件。省略時はすべての取得を上限超過にする。
   */
  goOversized(match?: (url: string) => boolean): void;
  /** 監査ログの記録先（`onPolicyEvent`）。 */
  onPolicyEvent(record: FailSafeAuditRecord): void;
  /** 常に同意するコールバック。 */
  requestConsent(decision: FailSafeDecision): boolean;
}

/**
 * URL → JWT のマップから FO-6 テスト用の環境を組み立てる。
 *
 * @param responses 応答マップ（`federation-fixtures.ts` の構築物をそのまま渡す）。
 * @returns 可変時計・オフライン切替・キャッシュ・監査シンクを備えた環境。
 */
export function failOpenHarness(responses: Map<string, string>): FailOpenHarness {
  let now = NOW_SECONDS;
  let offlineFor: ((url: string) => boolean) | undefined;
  let oversizedFor: ((url: string) => boolean) | undefined;
  const records: FailSafeAuditRecord[] = [];
  const consents: FailSafeDecision[] = [];
  const online = makeFetchMock(responses);
  const fetchFn = (async (input: string | URL): Promise<Response> => {
    const url = typeof input === 'string' ? input : input.toString();
    if (offlineFor?.(url) === true) {
      return new Response('unavailable', { status: 503 });
    }
    if (oversizedFor?.(url) === true) {
      // `content-length` は宣言せず、実バイト数の打ち切り（`readBodyWithinLimit`）側を通す。
      return new Response('x'.repeat(MAX_DOCUMENT_BYTES + 1), {
        status: 200,
        headers: { 'content-type': 'application/entity-statement+jwt' },
      });
    }
    return online(url);
  }) as typeof fetch;
  return {
    records,
    consents,
    base: {
      fetchFn,
      now: (): number => now * 1000,
      statementCache: createFederationStatementCache(() => now),
    },
    advance: (seconds: number): void => {
      now += seconds;
    },
    goOffline: (match?: (url: string) => boolean): void => {
      offlineFor = match ?? ((): boolean => true);
    },
    goOversized: (match?: (url: string) => boolean): void => {
      oversizedFor = match ?? ((): boolean => true);
    },
    onPolicyEvent: (record: FailSafeAuditRecord): void => {
      records.push(record);
    },
    requestConsent: (decision: FailSafeDecision): boolean => {
      consents.push(decision);
      return true;
    },
  };
}

/** reject が指定コードの VericertsError であることを検証する。 */
export async function expectRejectCode(
  promise: Promise<unknown>,
  code: ErrorCode,
): Promise<VericertsError> {
  let caught: unknown;
  try {
    await promise;
  } catch (error) {
    caught = error;
  }
  expect(caught).toBeInstanceOf(VericertsError);
  const failure = caught as VericertsError;
  expect(failure.code).toBe(code);
  return failure;
}
