/**
 * OID4VP 経路の PAR のプロトタイプ汚染耐性・相関 ID 伝播テスト。
 *
 * `oid4vci/__tests__/par/oid4vci-par.pollution.test.ts` / `oid4vci/par/__tests__/par-correlation.test.ts`
 * と同じ観点を、型を共有しない本経路に対して個別に確認する。
 */

import { describe, expect, test } from 'bun:test';
import { withPollutedPrototypeAsync } from '../../../__tests__/prototype-pollution.fixtures.js';
import { createCorrelationContext } from '../../../observability/correlation.js';
import { pushAuthorizationRequestForPresentation } from '../par.js';
import { baseRequest, type FetchCall, stubFetchOk, VALID_PAR_BODY } from './oid4vp-par-fixtures.js';

describe('OID4VPPARRequest.dpop の Object.prototype 汚染耐性', () => {
  const ATTACKER_PROOF = 'eyJ0eXAiOiJkcG9wK2p3dCJ9.attacker.sig';

  test('継承した dpop は DPoP ヘッダに載せない', async () => {
    const calls: FetchCall[] = [];
    await withPollutedPrototypeAsync({ dpop: ATTACKER_PROOF }, () =>
      pushAuthorizationRequestForPresentation(baseRequest(stubFetchOk(VALID_PAR_BODY, calls))),
    );
    expect(Object.hasOwn(calls[0]?.init.headers ?? {}, 'DPoP')).toBe(false);
  });

  test('汚染下でも明示的に渡した dpop はそのまま DPoP ヘッダに載る（正常系）', async () => {
    const calls: FetchCall[] = [];
    const proof = 'eyJ0eXAiOiJkcG9wK2p3dCJ9.legit.sig';
    await withPollutedPrototypeAsync({ dpop: ATTACKER_PROOF }, () =>
      pushAuthorizationRequestForPresentation({
        ...baseRequest(stubFetchOk(VALID_PAR_BODY, calls)),
        dpop: proof,
      }),
    );
    expect(calls[0]?.init.headers.DPoP).toBe(proof);
  });

  test('継承した client_assertion は body に載せない', async () => {
    const calls: FetchCall[] = [];
    await withPollutedPrototypeAsync(
      { client_assertion: 'attacker~assertion', client_assertion_type: 'attacker-type' },
      () =>
        pushAuthorizationRequestForPresentation(baseRequest(stubFetchOk(VALID_PAR_BODY, calls))),
    );
    expect(calls[0]?.body.has('client_assertion')).toBe(false);
    expect(calls[0]?.body.has('client_assertion_type')).toBe(false);
  });
});

describe('pushAuthorizationRequestForPresentation の相関 ID 伝播', () => {
  const CONTEXT = createCorrelationContext({ requestId: 'oid4vp-par-42', tracestate: 'rojo=1' });

  test('correlationContext 指定時は traceparent / X-Request-Id / tracestate を送る', async () => {
    const calls: FetchCall[] = [];
    await pushAuthorizationRequestForPresentation({
      ...baseRequest(stubFetchOk(VALID_PAR_BODY, calls)),
      correlationContext: CONTEXT,
    });

    expect(calls[0]?.init.headers.traceparent).toBe(CONTEXT.traceparent);
    expect(calls[0]?.init.headers['X-Request-Id']).toBe(CONTEXT.requestId);
    expect(calls[0]?.init.headers.tracestate).toBe('rojo=1');
    expect(calls[0]?.body.get('traceparent')).toBeNull();
  });

  test('未指定なら相関ヘッダを出さない（既存呼び出しの後方互換）', async () => {
    const calls: FetchCall[] = [];
    await pushAuthorizationRequestForPresentation(baseRequest(stubFetchOk(VALID_PAR_BODY, calls)));

    expect(calls).toHaveLength(1);
    expect(calls[0]?.init.headers.traceparent).toBeUndefined();
    expect(calls[0]?.init.headers['X-Request-Id']).toBeUndefined();
  });
});
