/**
 * 上限付き DID リゾルバ（`createBoundedResolver`）の検証。
 *
 * 重複排除（同一 DID は 1 回だけ）、同時実行数の上限、相異なる DID 数の上限（超過は下位 resolver を
 * 呼ばずに 2001）、および失敗 Promise の共有を確認する。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../errors.js';
import {
  createBoundedResolver,
  DEFAULT_MAX_DISTINCT_RESOLUTIONS,
  DEFAULT_MAX_RESOLUTION_CONCURRENCY,
  DEFAULT_MAX_TOTAL_DID_LENGTH,
  type DidResolverLike,
} from '../bounded-resolver.js';
import type { DIDDocument } from '../did.js';

/** テスト用の最小 DID Document。 */
function stubDocument(did: string): DIDDocument {
  return {
    '@context': ['https://www.w3.org/ns/did/v1'],
    id: did,
    verificationMethod: [],
    authentication: [],
    assertionMethod: [],
  };
}

/** 保留中のマイクロタスクを全て流す（セマフォの引き渡しは複数ティックにまたがる）。 */
function flushMicrotasks(): Promise<void> {
  return new Promise<void>((resume) => {
    setTimeout(resume, 0);
  });
}

/** 呼び出し DID を記録し、即座に解決する下位 resolver。 */
function recordingResolver(): DidResolverLike & { readonly calls: string[] } {
  const calls: string[] = [];
  return {
    calls,
    resolve(did: string): Promise<DIDDocument> {
      calls.push(did);
      return Promise.resolve(stubDocument(did));
    },
  };
}

/** 解決を手動で完了させられる下位 resolver（同時実行数のピークを記録する）。 */
function deferredResolver(): DidResolverLike & {
  readonly completions: Array<() => void>;
  readonly peak: () => number;
} {
  const completions: Array<() => void> = [];
  let active = 0;
  let peak = 0;
  return {
    completions,
    peak: () => peak,
    resolve(did: string): Promise<DIDDocument> {
      active += 1;
      peak = Math.max(peak, active);
      return new Promise<DIDDocument>((resolve) => {
        completions.push(() => {
          active -= 1;
          resolve(stubDocument(did));
        });
      });
    },
  };
}

describe('createBoundedResolver', () => {
  it('同一 DID を複数回解決しても下位 resolver は 1 回しか呼ばれない', async () => {
    const inner = recordingResolver();
    const bounded = createBoundedResolver(inner);
    const did = 'did:key:zSame';

    const documents = await Promise.all([
      bounded.resolve(did),
      bounded.resolve(did),
      bounded.resolve(did),
    ]);
    // 完了後の再解決も共有結果を返す（in-flight だけでなく完了済みも集約する）。
    documents.push(await bounded.resolve(did));

    expect(inner.calls).toEqual([did]);
    for (const document of documents) {
      expect(document.id).toBe(did);
    }
  });

  it('下位 resolver の同時実行数が maxConcurrency を超えない', async () => {
    const inner = deferredResolver();
    const maxConcurrency = 2;
    const bounded = createBoundedResolver(inner, { maxConcurrency });
    const dids = ['did:key:z1', 'did:key:z2', 'did:key:z3', 'did:key:z4', 'did:key:z5'];

    const pending = Promise.all(dids.map((did) => bounded.resolve(did)));
    // 待機キューに積まれた解決は下位 resolver へまだ渡っていない。
    await flushMicrotasks();
    expect(inner.completions).toHaveLength(maxConcurrency);

    // 完了させるたびに待機中の 1 件だけが起きる。全件を流し切ってピーク同時数を確認する。
    for (;;) {
      const complete = inner.completions.shift();
      if (complete === undefined) {
        break;
      }
      complete();
      await flushMicrotasks();
    }
    const documents = await pending;

    expect(documents.map((document) => document.id)).toEqual(dids);
    expect(inner.peak()).toBe(maxConcurrency);
  });

  it('maxDistinctDids を超える新しい DID は 2001 で reject し、下位 resolver を呼ばない', async () => {
    const inner = recordingResolver();
    const maxDistinctDids = 3;
    const bounded = createBoundedResolver(inner, { maxDistinctDids });

    for (let index = 0; index < maxDistinctDids; index += 1) {
      await bounded.resolve(`did:key:z${index}`);
    }
    await expect(bounded.resolve('did:key:zOverflow')).rejects.toThrow(
      new VericertsError(ErrorCodes.INVALID_DID),
    );

    expect(inner.calls).toHaveLength(maxDistinctDids);
    expect(inner.calls).not.toContain('did:key:zOverflow');
  });

  it('上限超過の例外は理由を持つが DID 文字列は含まない', async () => {
    const bounded = createBoundedResolver(recordingResolver(), { maxDistinctDids: 1 });
    await bounded.resolve('did:key:zAllowed');

    const error = await bounded.resolve('did:key:zSecret').catch((cause: unknown) => cause);
    expect(error).toBeInstanceOf(VericertsError);
    const failure = error as VericertsError;
    expect(failure.code).toBe(ErrorCodes.INVALID_DID);
    expect(failure.context).toEqual({ reason: 'resolution_fanout_limit' });
    expect(JSON.stringify(failure.context)).not.toContain('zSecret');
    expect(failure.message).not.toContain('zSecret');
  });

  it('上限に達した後でも既に解決を始めた DID は共有結果を返す', async () => {
    const inner = recordingResolver();
    const bounded = createBoundedResolver(inner, { maxDistinctDids: 1 });

    const first = await bounded.resolve('did:key:zKnown');
    const again = await bounded.resolve('did:key:zKnown');

    expect(again.id).toBe(first.id);
    expect(inner.calls).toEqual(['did:key:zKnown']);
  });

  it('失敗した DID の rejection は共有され、下位 resolver は再試行されない', async () => {
    const calls: string[] = [];
    const failure = new VericertsError(ErrorCodes.DID_NOT_FOUND);
    const inner: DidResolverLike = {
      resolve(did: string): Promise<DIDDocument> {
        calls.push(did);
        return Promise.reject(failure);
      },
    };
    const bounded = createBoundedResolver(inner);

    const first = await bounded.resolve('did:web:example.com').catch((cause: unknown) => cause);
    const second = await bounded.resolve('did:web:example.com').catch((cause: unknown) => cause);

    expect(first).toBe(failure);
    expect(second).toBe(failure);
    expect(calls).toEqual(['did:web:example.com']);
  });

  it('既定の上限は同時に解決する DID が 4 件、異なる DID が 32 件', () => {
    expect(DEFAULT_MAX_RESOLUTION_CONCURRENCY).toBe(4);
    expect(DEFAULT_MAX_DISTINCT_RESOLUTIONS).toBe(32);
  });

  it('maxTotalDidLength を超える新しい DID は 2001 で reject し、下位 resolver を呼ばない', async () => {
    const inner = recordingResolver();
    const bounded = createBoundedResolver(inner, { maxTotalDidLength: 20 });
    const first = 'did:key:z1234567'; // 16 文字
    const second = 'did:key:z7654321'; // 16 文字（合計 32 > 20）

    await bounded.resolve(first);
    const error = await bounded.resolve(second).catch((cause: unknown) => cause);

    expect(error).toBeInstanceOf(VericertsError);
    expect((error as VericertsError).code).toBe(ErrorCodes.INVALID_DID);
    expect((error as VericertsError).context).toEqual({ reason: 'resolution_cost_limit' });
    expect(inner.calls).toEqual([first]);
  });

  it('総量上限は重複 DID を二重計上せず、拒否された DID も計上しない', async () => {
    const inner = recordingResolver();
    const bounded = createBoundedResolver(inner, { maxTotalDidLength: 24 });
    const small = 'did:key:z1234567'; // 16 文字

    await bounded.resolve(small);
    await bounded.resolve(small);
    await expect(bounded.resolve('did:key:zOverflowing')).rejects.toThrow(VericertsError);
    // 拒否分が計上されていれば、残り 8 文字以内の DID も通らなくなる。
    await bounded.resolve('did:k:z');

    expect(inner.calls).toEqual([small, 'did:k:z']);
  });

  it('既定の DID 長合計上限は 16 KiB', () => {
    expect(DEFAULT_MAX_TOTAL_DID_LENGTH).toBe(16 * 1024);
  });
});
