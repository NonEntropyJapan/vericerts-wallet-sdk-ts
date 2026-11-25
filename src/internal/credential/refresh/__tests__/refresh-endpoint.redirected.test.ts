/**
 * `callRefreshEndpoint` の最終 URL 検査。
 *
 * `redirect: 'manual'` を渡しても、注入された `fetchImpl` が 3xx を追従して 200 を返すことがある。
 * 応答の最終 URL が非公開 / 非 HTTPS（`169.254.169.254` 等の内部宛）なら成功として受理せず
 * `REFRESH_FAILED`（3030）にする（manifest 応募経路の `isRedirectedResponse` 防御と同じ）。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes } from '../../../errors.js';
import type { RefreshServiceConfig, VerifiableCredential } from '../../vc/vc.js';
import { callRefreshEndpoint } from '../refresh-endpoint.js';

const SERVICE: RefreshServiceConfig = {
  id: 'refresh-1',
  type: 'OID4VCIRefreshService2025',
  url: 'https://issuer.example/refresh',
};
const VC = { id: 'urn:vc:1' } as unknown as VerifiableCredential;

/** `url` / `redirected` を差し込んだ 200 応答を返す fetch（実 fetch がリダイレクト追従した結果の再現）。 */
function followedRedirectFetch(finalUrl: string): typeof fetch {
  return (async () => {
    const response = new Response(JSON.stringify({ credential: '{"raw":"vc"}' }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    });
    Object.defineProperty(response, 'url', { value: finalUrl });
    Object.defineProperty(response, 'redirected', { value: true });
    return response;
  }) as unknown as typeof fetch;
}

describe('callRefreshEndpoint: 最終 URL の検査', () => {
  it.each([
    'http://169.254.169.254/latest/meta-data/',
    'https://10.0.0.5/x',
    'https://127.0.0.1/x',
    'http://issuer.example/refresh',
  ])('追従した結果の最終 URL が %s なら REFRESH_FAILED で拒否する', async (finalUrl) => {
    await expect(
      callRefreshEndpoint(SERVICE, VC, followedRedirectFetch(finalUrl)),
    ).rejects.toMatchObject({ code: ErrorCodes.REFRESH_FAILED });
  });

  it('最終 URL が公開 HTTPS（または空）の 200 応答は従来どおり受理する', async () => {
    await expect(
      callRefreshEndpoint(SERVICE, VC, followedRedirectFetch('https://issuer.example/refresh')),
    ).resolves.toBe('{"raw":"vc"}');
    await expect(callRefreshEndpoint(SERVICE, VC, followedRedirectFetch(''))).resolves.toBe(
      '{"raw":"vc"}',
    );
  });
});
