/**
 * PAR（RFC 9126）への相関 ID 伝播。
 *
 * SDK は OID4VCI の要求ヘッダで W3C Trace Context を伝播する。PAR は Authorization
 * Code Flow で AS へ出る**最初の**要求であり、ここが欠けると以降の Token / Credential と
 * 同じトレースに繋がらない。`dpop` と同じく body ではなくヘッダに載ること、未指定の呼び出しでは
 * ヘッダ自体が出ないこと（後方互換）を実際の送信記録から確認する。
 */

import { describe, expect, test } from 'bun:test';
import { createCorrelationContext } from '../../../../observability/correlation.js';
import {
  baseRequest,
  type FetchCall,
  stubFetchOk,
  VALID_PAR_BODY,
} from '../../__tests__/par/par-fixtures.js';
import { pushAuthorizationRequest } from '../index.js';

const CONTEXT = createCorrelationContext({ requestId: 'popup-click-42', tracestate: 'rojo=1' });

describe('pushAuthorizationRequest の相関 ID 伝播', () => {
  test('correlationContext 指定時は traceparent / X-Request-Id / tracestate を送る', async () => {
    const calls: FetchCall[] = [];
    await pushAuthorizationRequest({
      ...baseRequest(stubFetchOk(VALID_PAR_BODY, calls)),
      correlationContext: CONTEXT,
    });

    expect(calls[0]?.init.headers.traceparent).toBe(CONTEXT.traceparent);
    expect(calls[0]?.init.headers['X-Request-Id']).toBe(CONTEXT.requestId);
    expect(calls[0]?.init.headers.tracestate).toBe('rojo=1');
    // ワイヤの body には載せない（RFC 9126 のパラメータではない）。
    expect(calls[0]?.body.get('traceparent')).toBeNull();
  });

  test('未指定なら相関ヘッダを出さない（既存呼び出しの後方互換）', async () => {
    const calls: FetchCall[] = [];
    await pushAuthorizationRequest(baseRequest(stubFetchOk(VALID_PAR_BODY, calls)));

    // push 自体は出ている（ヘッダが無いことの検査が空振りしていないことの担保）。
    expect(calls).toHaveLength(1);
    expect(calls[0]?.init.headers.traceparent).toBeUndefined();
    expect(calls[0]?.init.headers['X-Request-Id']).toBeUndefined();
  });

  test('形の壊れた correlationContext は未指定として扱う（push は成立する）', async () => {
    const calls: FetchCall[] = [];
    const response = await pushAuthorizationRequest({
      ...baseRequest(stubFetchOk(VALID_PAR_BODY, calls)),
      correlationContext: { requestId: 'req-1', traceparent: 'broken' } as never,
    });

    // 相関 ID は観測の補助情報であり、その不備で PAR を止めない（correlation.ts の方針）。
    expect(response.request_uri).toBe(VALID_PAR_BODY.request_uri);
    expect(calls[0]?.init.headers.traceparent).toBeUndefined();
  });
});
