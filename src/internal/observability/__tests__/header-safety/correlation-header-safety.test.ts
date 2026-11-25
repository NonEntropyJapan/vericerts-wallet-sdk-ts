/**
 * 相関 ID のヘッダ適合性と tracestate のフィルタリングが手組み context でも効くこと。
 *
 * `createCorrelationContext` を通らない context は、(1) CRLF / 非 Latin-1 の `requestId` が
 * `Headers` の TypeError で OID4VP 提示送信を丸ごと失敗させ、(2) `tracestate` の `user.*` / `did:`
 * が Verifier へそのまま送出されていた。読み取り側（`isCorrelationContext` /
 * `readCorrelationContext`）と送出口（`correlationHeaders`）で `createCorrelationContext` と同じ
 * 不変条件を課す。
 */

import { describe, expect, it } from 'bun:test';
import {
  correlationHeaders,
  createCorrelationContext,
  isCorrelationContext,
  readCorrelationContext,
} from '../../correlation.js';

const TRACEPARENT = '00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01';

const UNSAFE_REQUEST_IDS: readonly (readonly [string, string])[] = [
  ['CRLF 注入', 'a\r\nX-Evil: 1'],
  ['改行のみ', 'a\nb'],
  ['非 Latin-1', 'リクエスト'],
  ['空白を含む', 'req 1'],
  ['129 文字', 'a'.repeat(129)],
  ['DID を含む', 'did:ethr:0xabcdef'],
];

describe('requestId のヘッダ適合性', () => {
  it.each(
    UNSAFE_REQUEST_IDS,
  )('%s の requestId は isCorrelationContext が受理しない', (_l, requestId) => {
    expect(isCorrelationContext({ requestId, traceparent: TRACEPARENT })).toBe(false);
  });

  it.each(
    UNSAFE_REQUEST_IDS,
  )('%s の requestId は readCorrelationContext が undefined へ倒す', (_l, requestId) => {
    expect(
      readCorrelationContext({ correlationContext: { requestId, traceparent: TRACEPARENT } }),
    ).toBeUndefined();
  });

  it.each(
    UNSAFE_REQUEST_IDS,
  )('%s の requestId は createCorrelationContext が新規生成に置き換える', (_l, requestId) => {
    const context = createCorrelationContext({ requestId });
    expect(context.requestId).toMatch(/^[0-9a-f]{32}$/);
    expect(isCorrelationContext(context)).toBe(true);
  });

  it.each(
    UNSAFE_REQUEST_IDS,
  )('%s の requestId を持つ手組み context でも correlationHeaders は Headers を構築できる', (_l, requestId) => {
    const headers = correlationHeaders({ requestId, traceparent: TRACEPARENT });
    expect(() => new Headers(headers)).not.toThrow();
    expect(headers['X-Request-Id']).toBeUndefined();
    expect(headers.traceparent).toBe(TRACEPARENT);
  });

  it('可視 ASCII 1〜128 文字の requestId（境界）はそのまま使う', () => {
    for (const requestId of ['a', 'popup-click-42', 'a'.repeat(128), '!~']) {
      expect(isCorrelationContext({ requestId, traceparent: TRACEPARENT })).toBe(true);
      expect(createCorrelationContext({ requestId }).requestId).toBe(requestId);
      expect(correlationHeaders({ requestId, traceparent: TRACEPARENT })['X-Request-Id']).toBe(
        requestId,
      );
    }
  });
});

describe('手組み context の tracestate strip', () => {
  const tracestate = 'user.id=alice,x=did:ethr:0xabc,vendor=ok';

  it('readCorrelationContext は user.* / did: を落とした tracestate を返す', () => {
    const context = readCorrelationContext({
      correlationContext: { requestId: 'req-1', traceparent: TRACEPARENT, tracestate },
    });
    expect(context?.tracestate).toBe('vendor=ok');
  });

  it('strip で全滅した tracestate は持たない', () => {
    const context = readCorrelationContext({
      correlationContext: {
        requestId: 'req-1',
        traceparent: TRACEPARENT,
        tracestate: 'user.id=alice',
      },
    });
    expect(context).toEqual({ requestId: 'req-1', traceparent: TRACEPARENT });
    expect(Object.hasOwn(context as object, 'tracestate')).toBe(false);
  });

  it('createCorrelationContext 経由と同じ結果になる', () => {
    const viaCreate = createCorrelationContext({
      requestId: 'req-1',
      traceparent: TRACEPARENT,
      tracestate,
    });
    const viaRead = readCorrelationContext({
      correlationContext: { requestId: 'req-1', traceparent: TRACEPARENT, tracestate },
    });
    expect(viaRead).toEqual(viaCreate);
  });

  it('correlationHeaders は型付きの手組み context の user.* / did: も送出しない', () => {
    const headers = correlationHeaders({
      requestId: 'req-1',
      traceparent: TRACEPARENT,
      tracestate,
    });
    expect(headers.tracestate).toBe('vendor=ok');
    expect(
      correlationHeaders({ requestId: 'req-1', traceparent: TRACEPARENT, tracestate: 'user.id=a' }),
    ).not.toHaveProperty('tracestate');
  });
});
