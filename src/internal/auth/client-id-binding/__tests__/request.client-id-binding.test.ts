/**
 * OID4VP 直接形式の `client_id` ↔ `response_uri` origin 束縛（SIOPv2 と共通）。
 *
 * 署名なしのクエリでは `client_id` を攻撃者が自由に決められる。origin を取れない識別子
 * （スキームなし / prefixed / DID）や userinfo 付き URL を受理すると、同意 UI の表示 RP と
 * VP Token の送信先（`response_uri`）が食い違う。いずれも 8030 で fail-closed に拒否する。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import { parseAuthorizationRequest } from '../../request.js';

const EVIL_RESPONSE_URI = 'https://evil.example/cb';

function buildUri(clientId: string, responseUri: string): string {
  const search = new URLSearchParams({
    response_type: 'vp_token',
    client_id: clientId,
    response_mode: 'direct_post',
    response_uri: responseUri,
    nonce: 'N-0123456789abcdefghijk',
    state: 'S',
  });
  return `openid4vp://?${search.toString()}`;
}

function reasonOf(uri: string): unknown {
  try {
    parseAuthorizationRequest(uri);
  } catch (err) {
    expect(err).toBeInstanceOf(VericertsError);
    expect((err as VericertsError).code).toBe(ErrorCodes.OID4VP_REQUEST_PARSE_FAILED);
    return (err as VericertsError).context?.['reason'];
  }
  throw new Error('should have thrown');
}

describe('parseAuthorizationRequest: client_id の origin 束縛', () => {
  it.each([
    ['スキームなしのドメイン', 'victim.example.com'],
    ['x509_san_dns: prefixed', 'x509_san_dns:victim.example.com'],
    ['スキームなしの任意識別子', 'victim-rp'],
  ])('%s は origin が取れないため client_id_not_url で拒否する', (_label, clientId) => {
    expect(reasonOf(buildUri(clientId, EVIL_RESPONSE_URI))).toBe('client_id_not_url');
  });

  it('DID 形式の client_id は origin が取れないため拒否する', () => {
    expect(reasonOf(buildUri('did:web:victim.example.com', EVIL_RESPONSE_URI))).toBe(
      'client_id_not_url',
    );
  });

  it('userinfo 付き client_id は response_uri と origin が一致しても拒否する', () => {
    expect(reasonOf(buildUri('https://bank.example@evil.example', EVIL_RESPONSE_URI))).toBe(
      'client_id_not_url',
    );
    expect(reasonOf(buildUri('https://bank.example:pw@evil.example', EVIL_RESPONSE_URI))).toBe(
      'client_id_not_url',
    );
  });

  it('origin が異なる https URL は従来どおり response_uri_client_id_mismatch', () => {
    expect(reasonOf(buildUri('https://victim.example.com', EVIL_RESPONSE_URI))).toBe(
      'response_uri_client_id_mismatch',
    );
  });

  it('同一 origin の https URL は受理する', () => {
    const uri = buildUri('https://verifier.example.com', 'https://verifier.example.com/cb');
    expect(parseAuthorizationRequest(uri).clientId).toBe('https://verifier.example.com');
  });
});
