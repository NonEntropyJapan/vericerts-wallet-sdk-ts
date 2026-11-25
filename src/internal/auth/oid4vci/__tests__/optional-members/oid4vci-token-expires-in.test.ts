/**
 * Token Response の `expires_in` は任意（RFC 6749 §5.1 で RECOMMENDED）。
 *
 * 旧実装は `expires_in` を必須扱いし、省略する AS の応答を 8010 で拒否していた
 * （値は SDK / extension のどこからも消費されない）。省略は受理して `expiresIn` を
 * `undefined` にし、存在する場合だけ型（有限の非負数）を検査して不正なら 8010 に倒す。
 */

import { afterEach, describe, expect, it } from 'bun:test';
import { ErrorCodes } from '../../../../errors.js';
import { requestTokenPreAuthorized } from '../../token/oid4vci-token.js';
import { parseTokenResponse } from '../../token/oid4vci-token-http.js';
import { type FetchCall, stubFetchOk, VALID_TOKEN_BODY } from '../token/token-fixtures.js';

const TOKEN_ENDPOINT = 'https://issuer.example.com/token';
const MINIMAL_BODY = { access_token: 'a', token_type: 'Bearer' } as const;

const originalFetch = globalThis.fetch;

afterEach(() => {
  globalThis.fetch = originalFetch;
});

describe('parseTokenResponse: expires_in は任意', () => {
  it('expires_in を省略した応答を受理し expiresIn は undefined になる', () => {
    const result = parseTokenResponse({ ...MINIMAL_BODY });

    expect(result.accessToken).toBe('a');
    expect(result.expiresIn).toBeUndefined();
    expect(Object.hasOwn(result, 'expiresIn')).toBe(false);
  });

  it('存在する有限の非負数（0 / 数値文字列を含む）は採用する', () => {
    expect(parseTokenResponse({ ...MINIMAL_BODY, expires_in: 3600 }).expiresIn).toBe(3600);
    expect(parseTokenResponse({ ...MINIMAL_BODY, expires_in: 0 }).expiresIn).toBe(0);
    expect(parseTokenResponse({ ...MINIMAL_BODY, expires_in: '90' }).expiresIn).toBe(90);
  });

  it.each([
    ['非数値文字列', 'abc'],
    ['負値', -5],
    ['負値の文字列', '-5'],
    ['NaN 相当の文字列', 'NaN'],
    ['null', null],
    ['真偽値', true],
    ['空文字', ''],
  ])('指定された expires_in が不正（%s）なら 8010 で拒否する', (_label, value) => {
    expect(() => parseTokenResponse({ ...MINIMAL_BODY, expires_in: value })).toThrow(
      expect.objectContaining({ code: ErrorCodes.TOKEN_REQUEST_FAILED }),
    );
  });

  it('access_token / token_type の欠落は従来どおり 8010（expires_in の任意化で緩めない）', () => {
    expect(() => parseTokenResponse({ token_type: 'Bearer', expires_in: 3600 })).toThrow(
      expect.objectContaining({ code: ErrorCodes.TOKEN_REQUEST_FAILED }),
    );
    expect(() => parseTokenResponse({ access_token: 'a', expires_in: 3600 })).toThrow(
      expect.objectContaining({ code: ErrorCodes.TOKEN_REQUEST_FAILED }),
    );
  });
});

describe('requestTokenPreAuthorized: expires_in 省略の AS 応答', () => {
  it('expires_in を省略する AS からも access_token を取得できる', async () => {
    const calls: FetchCall[] = [];
    stubFetchOk(calls, { ...MINIMAL_BODY });

    const res = await requestTokenPreAuthorized(TOKEN_ENDPOINT, { preAuthorizedCode: 'c' });

    expect(res.accessToken).toBe('a');
    expect(res.expiresIn).toBeUndefined();
  });

  it('負の expires_in は 8010 で拒否する', async () => {
    stubFetchOk([], { ...VALID_TOKEN_BODY, expires_in: -5 });

    await expect(
      requestTokenPreAuthorized(TOKEN_ENDPOINT, { preAuthorizedCode: 'c' }),
    ).rejects.toMatchObject({ code: ErrorCodes.TOKEN_REQUEST_FAILED });
  });
});
