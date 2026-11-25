/**
 * OID4VP `response_uri` の公開ホスト検査。
 *
 * Verifier が選ぶ `response_uri` がループバック / プライベート / リンクローカル宛のとき、
 * VP Token を POST しない（SSRF）。要求受理時（`parseAuthorizationRequest`）と提出時
 * （`submitPresentation`）の両方で拒否する。
 */

import { afterEach, describe, expect, it } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import { RESPONSE_MODE_DIRECT_POST, submitPresentation } from '../../oid4vp/oid4vp-submit.js';
import type { PresentationRequest } from '../../request.js';

const PRIVATE_HOSTS = [
  'https://10.0.0.5/callback',
  'https://127.0.0.1/callback',
  'https://192.168.1.1/callback',
  'https://169.254.169.254/callback',
  'https://localhost/callback',
];

const originalFetch = globalThis.fetch;
afterEach(() => {
  globalThis.fetch = originalFetch;
});

function requestFor(responseUri: string): PresentationRequest {
  return {
    responseType: 'vp_token',
    clientId: new URL(responseUri).origin,
    responseMode: RESPONSE_MODE_DIRECT_POST,
    responseUri,
    nonce: 'n-0S6_WzA2Mj',
    state: 's',
  } as PresentationRequest;
}

describe('submitPresentation: 非公開ホスト宛 response_uri', () => {
  it.each(PRIVATE_HOSTS)('%s へは fetch せず 8035 で拒否する', async (uri) => {
    let called = false;
    globalThis.fetch = (async () => {
      called = true;
      return new Response(null, { status: 200 });
    }) as unknown as typeof fetch;
    await expect(submitPresentation(requestFor(uri), 'vp')).rejects.toMatchObject({
      code: ErrorCodes.PRESENTATION_SUBMIT_FAILED,
    });
    expect(called).toBe(false);
  });

  it('公開ホスト宛は従来どおり POST する', async () => {
    const urls: string[] = [];
    globalThis.fetch = (async (input: string) => {
      urls.push(String(input));
      return new Response(null, { status: 200 });
    }) as unknown as typeof fetch;
    await submitPresentation(requestFor('https://verifier.example.com/callback'), 'vp');
    expect(urls).toEqual(['https://verifier.example.com/callback']);
  });
});

describe('parseAuthorizationRequest: 非公開ホスト宛 response_uri', () => {
  it.each(PRIVATE_HOSTS)('%s は client_id が同一オリジンでも 8030 で拒否する', async (uri) => {
    const { parseAuthorizationRequest } = await import('../../request.js');
    const params = new URLSearchParams({
      response_type: 'vp_token',
      client_id: new URL(uri).origin,
      response_mode: 'direct_post',
      response_uri: uri,
      nonce: 'n-0S6_WzA2Mj',
      state: 's',
      dcql_query: JSON.stringify({ credentials: [{ id: 'c', format: 'jwt_vc_json' }] }),
    });
    let caught: unknown;
    try {
      parseAuthorizationRequest(`openid4vp://authorize?${params.toString()}`);
    } catch (error) {
      caught = error;
    }
    expect(caught).toBeInstanceOf(VericertsError);
    expect((caught as VericertsError).code).toBe(ErrorCodes.OID4VP_REQUEST_PARSE_FAILED);
  });
});
