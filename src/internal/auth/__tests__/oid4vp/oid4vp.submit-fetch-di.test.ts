/**
 * `submitPresentation` の `fetchImpl` DI シームのテストと、その DI シームで観測する
 * 相関 ID 伝播のテスト。
 *
 * EUDI の提示フロー（`internal/eudi/presentation`）を実ネットワーク無しで検証するため、
 * VP Token 送信にも OID4VCI 経路と同じ DI シームを追加した。ここでは注入した実装が実際に
 * 使われること・`redirect: 'manual'` が注入側にも渡ること（リダイレクト不追従を
 * 注入実装でも成立させるため）・`Object.prototype` 由来の値を採用しないことを検証する。
 *
 * 相関 ID の検証も同じ注入 fetch で送信ヘッダ / 本文を捕捉するため本ファイルに置く。OID4VCI 側の
 * 同じ不変条件は `__tests__/oid4vci/oid4vci-correlation.test.ts` が持つ。
 */

import { describe, expect, it } from 'bun:test';
import { withPollutedPrototypeAsync } from '../../../__tests__/prototype-pollution.fixtures.js';
import { createCorrelationContext } from '../../../observability/correlation.js';
import type { SubmitFetchLike } from '../../oid4vp/oid4vp-submit.js';
import { submitPresentation } from '../../oid4vp/oid4vp-submit.js';
import type { PresentationRequest } from '../../request.js';
import { sampleRequest } from './direct-post-jwt/direct-post-jwt.fixtures.js';

const REQUEST: PresentationRequest = {
  responseType: 'vp_token',
  clientId: 'https://verifier.example.com',
  responseMode: 'direct_post',
  responseUri: 'https://verifier.example.com/response',
  nonce: 'n-0S6_WzA2Mj',
  state: 'state-123',
};

const VP_TOKEN = 'eyJhbGci.issuer.jwt~WyJzYWx0IiwiZmFtaWx5X25hbWUiLCJEb2UiXQ~';

describe('submitPresentation / fetchImpl DI', () => {
  it('注入した fetchImpl で送信し、redirect: manual を渡す', async () => {
    const calls: { url: string; redirect: RequestRedirect; body: string }[] = [];
    const fetchImpl: SubmitFetchLike = (url, init) => {
      calls.push({ url, redirect: init.redirect, body: init.body });
      return Promise.resolve(new Response('', { status: 200 }));
    };
    await submitPresentation(REQUEST, VP_TOKEN, { fetchImpl });
    expect(calls).toHaveLength(1);
    expect(calls[0]?.url).toBe(REQUEST.responseUri);
    expect(calls[0]?.redirect).toBe('manual');
    const body = new URLSearchParams(calls[0]?.body ?? '');
    expect(body.get('vp_token')).toBe(VP_TOKEN);
    expect(body.get('state')).toBe(REQUEST.state);
  });

  it('Object.prototype 由来の fetchImpl は採用しない', async () => {
    const attacker = { called: false };
    const polluted: SubmitFetchLike = () => {
      attacker.called = true;
      return Promise.resolve(new Response('', { status: 200 }));
    };
    const originalFetch = globalThis.fetch;
    let globalCalled = false;
    globalThis.fetch = (() => {
      globalCalled = true;
      return Promise.resolve(new Response('', { status: 200 }));
    }) as unknown as typeof fetch;
    try {
      await withPollutedPrototypeAsync({ fetchImpl: polluted }, async () => {
        await submitPresentation(REQUEST, VP_TOKEN);
      });
    } finally {
      globalThis.fetch = originalFetch;
    }
    expect(attacker.called).toBe(false);
    expect(globalCalled).toBe(true);
  });
});

/** 未指定時に送るべきヘッダ（相関 ID 追加前の挙動）。 */
const BASE_HEADERS = { 'Content-Type': 'application/x-www-form-urlencoded' };

const CONTEXT = createCorrelationContext({ requestId: 'popup-click-42', tracestate: 'rojo=1' });

/** 送信ヘッダと本文を記録するスタブ。 */
function captureFetch(): {
  fetchImpl: SubmitFetchLike;
  sent: { headers: Record<string, string>; body: string }[];
} {
  const sent: { headers: Record<string, string>; body: string }[] = [];
  const fetchImpl: SubmitFetchLike = (_url, init) => {
    sent.push({ headers: init.headers, body: init.body });
    return Promise.resolve(new Response('', { status: 200 }));
  };
  return { fetchImpl, sent };
}

// 平文 / 暗号化のどちらも同じ `postForm` を通るため、相関 ID の扱いは response_mode に依らない。
const RESPONSE_MODES: readonly [string, () => PresentationRequest][] = [
  ['direct_post', () => REQUEST],
  ['direct_post.jwt', () => sampleRequest()],
];

describe.each(RESPONSE_MODES)('submitPresentation / 相関 ID 伝播 — %s', (_mode, buildRequest) => {
  it('correlationContext を渡すと traceparent / X-Request-Id / tracestate を載せる', async () => {
    const { fetchImpl, sent } = captureFetch();
    await submitPresentation(buildRequest(), VP_TOKEN, {
      fetchImpl,
      correlationContext: CONTEXT,
    });
    expect(sent[0]?.headers.traceparent).toBe(CONTEXT.traceparent);
    expect(sent[0]?.headers['X-Request-Id']).toBe(CONTEXT.requestId);
    expect(sent[0]?.headers.tracestate).toBe('rojo=1');
  });

  it('相関 ID はヘッダのみに載り、フォーム本文には現れない', async () => {
    const { fetchImpl, sent } = captureFetch();
    await submitPresentation(buildRequest(), VP_TOKEN, {
      fetchImpl,
      correlationContext: CONTEXT,
    });
    // 本文は VP Token（direct_post）ないし JWE（direct_post.jwt）のみ。観測用の値は混ぜない。
    const body = sent[0]?.body ?? '';
    for (const value of [CONTEXT.traceparent, CONTEXT.requestId, 'rojo=1']) {
      expect(body).not.toContain(value);
    }
  });

  it.each([
    ['未指定', undefined],
    // 形が壊れた値は未指定として扱う（`readCorrelationContext` の fail-safe。送信は止めない）。
    ['形が壊れた値', { traceparent: 123 } as never],
  ])('%s のときはヘッダを相関 ID 追加前と同一にする', async (_label, correlationContext) => {
    const { fetchImpl, sent } = captureFetch();
    await submitPresentation(buildRequest(), VP_TOKEN, { fetchImpl, correlationContext });
    expect(sent[0]?.headers).toEqual(BASE_HEADERS);
  });
});
