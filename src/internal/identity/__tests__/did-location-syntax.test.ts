/**
 * did:webvh の解決入力に対する domain・path 文字種検証。
 *
 * `? # @ \` や `.` / `..`（`%2e` 含む）で DID Log の取得先が DID の示す場所からずれないことを確認する
 * （生成側 `assertDidLocation` と同じ規則。did:web 側は `web/__tests__/method-web.url.test.ts`）。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../errors.js';
import { didWebToUrl } from '../web/method-web.js';
import { parseWebVh, webVhLogUrl } from '../webvh/did-url.js';
import { assertDidLocation } from '../webvh/lifecycle/did-location.js';

const SCID = `Qm${'S'.repeat(44)}`;

// 解決入力の domain / path は生成側（assertDidLocation）と同じ文字種に限る。
const MALFORMED_LOCATIONS = [
  'example.com?x=1',
  'example.com#x',
  'user@evil.com',
  'example.com:..:x',
  'example.com:.:x',
  'example.com:a:%2e%2e:b',
  'example.com:a?b',
  'example.com:a#b',
  'example.com:a%2Fb',
  'example.com:a\\b',
  'example.com%3Aabc',
  'exa mple.com',
];

describe('parseWebVh / webVhLogUrl 文字種検証', () => {
  it.each(MALFORMED_LOCATIONS)('parseWebVh は %s を 2001 で拒否する', (location) => {
    expect(() => parseWebVh(`did:webvh:${SCID}:${location}`)).toThrow(
      new VericertsError(ErrorCodes.INVALID_DID),
    );
  });

  it('webVhLogUrl は手組みの不正な domain / path も 2001 で拒否する', () => {
    const invalid = new VericertsError(ErrorCodes.INVALID_DID);
    expect(() => webVhLogUrl({ scid: SCID, domain: 'example.com?x=1', pathSegments: [] })).toThrow(
      invalid,
    );
    expect(() => webVhLogUrl({ scid: SCID, domain: 'example.com', pathSegments: ['..'] })).toThrow(
      invalid,
    );
  });

  it('許可文字（%3A ポート・. - _・%7E）は受理し、URL では RFC 3986 に従って再エンコードする', () => {
    const parsed = parseWebVh(
      `did:webvh:${SCID}:Example.com%3A8443:a.b-c_d%7Ee:%E7%94%A8%E6%88%B7`,
    );
    expect(webVhLogUrl(parsed)).toBe(
      'https://example.com:8443/a.b-c_d~e/%E7%94%A8%E6%88%B7/did.jsonl',
    );
  });

  // 仕様の ABNF: path セグメントは DID Core の idchar（`~` や生の Unicode は含まない。`%XX` で表す）。
  it.each([
    'a~b',
    '用户',
    'a%2Fb',
    'a%5Cb',
    'a%00b',
    'a%20',
    '%20a',
  ])('path セグメント %s は拒否する', (segment) => {
    expect(() => parseWebVh(`did:webvh:${SCID}:example.com:${segment}`)).toThrow(
      new VericertsError(ErrorCodes.INVALID_DID),
    );
  });
});

// 区切りは大文字 `%3A` のみ・ポートは 1〜65535。正規化されない別表記を DID として成立させない。
const NON_CANONICAL_PORTS = [
  'example.com%3a8443',
  'example.com%3A0',
  'example.com%3A08443',
  'example.com%3A65536',
  'example.com%3A99999',
  'example.com%3A123456',
  'example.com%3A',
];

describe('非正規なポート表記の拒否', () => {
  const invalid = new VericertsError(ErrorCodes.INVALID_DID);

  it.each(
    NON_CANONICAL_PORTS,
  )('parseWebVh / didWebToUrl / assertDidLocation は %s を 2001 で拒否する', (domain) => {
    expect(() => parseWebVh(`did:webvh:${SCID}:${domain}`)).toThrow(invalid);
    expect(() => didWebToUrl(`did:web:${domain}`)).toThrow(invalid);
    expect(() => assertDidLocation(domain, undefined)).toThrow(invalid);
  });

  it.each(['1', '443', '8443', '60000', '65535'])('ポート %s は受理する', (port) => {
    const domain = `example.com%3A${port}`;
    expect(() => assertDidLocation(domain, undefined)).not.toThrow();
    expect(new URL(didWebToUrl(`did:web:${domain}`)).port).toBe(port === '443' ? '' : port);
  });
});
