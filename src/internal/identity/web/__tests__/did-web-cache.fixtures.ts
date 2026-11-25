/**
 * did:web キャッシュ層テストの共有フィクスチャ。
 *
 * 注入する `fetchFn` と時計を組み立てるヘルパ群。`method-web.cache.test.ts`（TTL 挙動）と
 * `method-web.cache-negative.test.ts`（negative cache / 設定拒否）から共用する。
 * モックレスポンスの構築方式は `method-web.resolve.test.ts` に合わせている。
 */

import { expect } from 'bun:test';
import { type ErrorCode, VericertsError } from '../../../errors.js';
import type { DIDDocument } from '../../did.js';
import type { DidWebCacheEvent } from '../did-web-cache.js';

/** テスト対象の did:web 文字列。 */
export const DID = 'did:web:example.com';

/** `DID` の取得先 URL。 */
export const EXPECTED_URL = 'https://example.com/.well-known/did.json';

/** 正常系で返す DID Document。 */
export const SAMPLE_DOC: DIDDocument = {
  '@context': ['https://www.w3.org/ns/did/v1'],
  id: DID,
  verificationMethod: [
    {
      id: `${DID}#key-1`,
      type: 'Ed25519VerificationKey2020',
      controller: DID,
      publicKeyMultibase: 'z6MkExample',
    },
  ],
  authentication: [`${DID}#key-1`],
  assertionMethod: [`${DID}#key-1`],
};

/** モックレスポンスを構築する。 */
export function mockResponse(opts: {
  body: string;
  status?: number;
  contentType?: string | null;
  cacheControl?: string;
  url?: string;
}): Response {
  const headers = new Headers();
  if (opts.contentType !== null && opts.contentType !== undefined) {
    headers.set('content-type', opts.contentType);
  }
  if (opts.cacheControl !== undefined) {
    headers.set('cache-control', opts.cacheControl);
  }
  const response = new Response(opts.body, { status: opts.status ?? 200, headers });
  // Response の url は読み取り専用のため defineProperty で上書きする。
  Object.defineProperty(response, 'url', { value: opts.url ?? EXPECTED_URL, configurable: true });
  return response;
}

/** 呼び出し回数を数えるモック fetch。 */
export interface CountingFetch {
  /** 注入する fetch 実装。 */
  readonly fetchFn: typeof fetch;
  /** これまでの呼び出し回数。 */
  calls(): number;
}

/** 任意のレスポンスを返し、呼び出し回数を数える fetch を作る。 */
export function countingFetch(impl: () => Response): CountingFetch {
  let calls = 0;
  const fetchFn = (async () => {
    calls += 1;
    return impl();
  }) as unknown as typeof fetch;
  return { fetchFn, calls: () => calls };
}

/** 404（取得失敗）を返す fetch を作る。 */
export function notFoundFetch(): CountingFetch {
  return countingFetch(() =>
    mockResponse({ body: 'Not Found', status: 404, contentType: 'text/plain' }),
  );
}

/** `SAMPLE_DOC` を返す fetch を作る（`cacheControl` 省略時はヘッダ無し）。 */
export function okFetch(cacheControl?: string): CountingFetch {
  return countingFetch(() =>
    mockResponse(
      cacheControl === undefined
        ? { body: JSON.stringify(SAMPLE_DOC), contentType: 'application/did+json' }
        : { body: JSON.stringify(SAMPLE_DOC), contentType: 'application/did+json', cacheControl },
    ),
  );
}

/** 手動で進められる固定時計。 */
export interface FixedClock {
  /** 現在時刻（エポック秒）。 */
  now(): number;
  /** 時計を進める。 */
  advance(seconds: number): void;
}

/** 固定時計を作る。 */
export function fixedClock(start = 1_000_000): FixedClock {
  let current = start;
  return {
    now: () => current,
    advance: (seconds: number) => {
      current += seconds;
    },
  };
}

/** 観測イベントを収集するフック。 */
export interface CacheEventRecorder {
  /** `deps.onCacheEvent` に渡すフック。 */
  onCacheEvent(event: DidWebCacheEvent): void;
  /** 記録された状態ラベルの列。 */
  readonly states: string[];
}

/** 観測イベントレコーダを作る。 */
export function recorder(): CacheEventRecorder {
  const states: string[] = [];
  return {
    onCacheEvent: (event: DidWebCacheEvent) => {
      states.push(event.state);
    },
    states,
  };
}

/** reject が指定コードの VericertsError であることを検証し、その例外を返す。 */
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
  expect((caught as VericertsError).code).toBe(code);
  return caught as VericertsError;
}
