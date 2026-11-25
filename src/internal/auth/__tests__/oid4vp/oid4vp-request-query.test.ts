/**
 * `oid4vp-request-query.ts` の参照形式判定。
 *
 * 判定は 2 つの入口（同期の `parseAuthorizationRequest` と非同期の `parsePresentationRequest`）が
 * 共有する 1 つの実装であり、片方だけ条件がずれると「Verifier が署名した Request Object ではなく
 * 署名の無いクエリパラメータが採用される」事故になる。ここでは判定そのものと、同期入口が混在を
 * fail-closed に拒否することを固定する（取得側の挙動は `jar/__tests__/` が固定する）。
 *
 * 混在（`request_uri` と直接パラメータの併記）を参照形式とするのは RFC 9101 の規定による:
 * §5.2.1 は互換性のためのクエリ重複送信を認め、§6.3 は Request Object 内のパラメータのみを使う
 * ことを要求する。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes, type VericertsError } from '../../../errors.js';
import { extractQuery, requestUriReferenceOf } from '../../oid4vp/oid4vp-request-query.js';
import { parseAuthorizationRequest } from '../../request.js';

const REQUEST_URI = 'https://verifier.example.com/request/123';
const CLIENT_ID = 'https://verifier.example.com';

/** 直接形式の完全なクエリ（必須パラメータが揃っている）。 */
function directParams(overrides: Record<string, string> = {}): URLSearchParams {
  return new URLSearchParams({
    response_type: 'vp_token',
    client_id: CLIENT_ID,
    response_mode: 'direct_post',
    response_uri: 'https://verifier.example.com/callback',
    nonce: 'n-direct-0123456789abcdef',
    state: 's-direct',
    ...overrides,
  });
}

describe('requestUriReferenceOf: 参照形式の判定（RFC 9101 §6.3）', () => {
  it('request_uri 単独は参照形式', () => {
    const query = extractQuery(`openid4vp://?request_uri=${encodeURIComponent(REQUEST_URI)}`);
    expect(requestUriReferenceOf(query)).toBe(REQUEST_URI);
  });

  it('request_uri と response_type の混在も参照形式（Request Object が勝つ）', () => {
    const query = extractQuery(`openid4vp://?${directParams({ request_uri: REQUEST_URI })}`);
    expect(requestUriReferenceOf(query)).toBe(REQUEST_URI);
  });

  it('request_uri が無ければ直接形式', () => {
    expect(requestUriReferenceOf(extractQuery(`openid4vp://?${directParams()}`))).toBeUndefined();
  });

  it('空の request_uri は参照形式と見なさない（直接形式の検証へ回す）', () => {
    const query = extractQuery(`openid4vp://?${directParams({ request_uri: '' })}`);
    expect(requestUriReferenceOf(query)).toBeUndefined();
  });

  it('空白のみの request_uri も参照形式と見なさない（isNonBlankString 規則）', () => {
    // 非空判定はコードベース共通の `isNonBlankString` に揃える。
    // `length === 0` の直書きだと ' ' が参照形式と判定され、取得もできない URL のまま
    // `request_uri_reference` を投げるだけで直接形式の必須パラメータ検証へ到達しない。
    // NBSP（U+00A0）・全角スペース（U+3000）も `trim` の対象なので同様に弾く。
    for (const blank of [' ', '\t', '\u00a0', '\u3000', '   \n ']) {
      const query = extractQuery(`openid4vp://?${directParams({ request_uri: blank })}`);
      expect(requestUriReferenceOf(query)).toBeUndefined();
    }
  });
});

describe('parseAuthorizationRequest: 同期入口は参照形式を fail-closed に拒否', () => {
  it('request_uri と直接パラメータの混在も 8030（request_uri_reference）', () => {
    // 同期関数は HTTP 取得ができない。黙って直接形式として扱うと、署名済み Request Object を
    // 捨てて署名の無いクエリを DCQL 評価と VP 送信先決定に採用してしまう。
    try {
      parseAuthorizationRequest(`openid4vp://?${directParams({ request_uri: REQUEST_URI })}`);
      throw new Error('should have thrown');
    } catch (err) {
      const error = err as VericertsError;
      expect(error.code).toBe(ErrorCodes.OID4VP_REQUEST_PARSE_FAILED);
      expect(error.context).toMatchObject({ reason: 'request_uri_reference' });
    }
  });

  it('空の request_uri 併記は参照形式扱いにならず直接形式として解析される', () => {
    const request = parseAuthorizationRequest(`openid4vp://?${directParams({ request_uri: '' })}`);
    expect(request.nonce).toBe('n-direct-0123456789abcdef');
  });

  it('空白のみの request_uri 併記も直接形式として解析される（8030 にならない）', () => {
    const request = parseAuthorizationRequest(
      `openid4vp://?${directParams({ request_uri: '   ' })}`,
    );
    expect(request.nonce).toBe('n-direct-0123456789abcdef');
  });
});
