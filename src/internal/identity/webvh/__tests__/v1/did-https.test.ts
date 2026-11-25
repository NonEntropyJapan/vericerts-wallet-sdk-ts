/**
 * did:webvh → HTTPS URL の変換（did:webvh v1.0、spec: Method-Specific Identifier、The DID to HTTPS Transformation）。
 * 国際化ドメイン名（IDNA）・パーセントエンコードの検証・IP ホスト・パス走査・witness proof ファイルの URL と取得。
 */

import { afterEach, describe, expect, it } from 'bun:test';
import {
  DID_WITNESS_MEDIA_TYPES,
  fetchDidLog,
  parseWebVh,
  webVhLogUrl,
  webVhWitnessUrl,
} from '../../did-url.js';
import { restoreFetch } from '../webvh-fixtures.js';
import { INVALID_DID } from './log-builders.js';

const SCID = `Qm${'S'.repeat(44)}`;
const urlOf = (location: string) => webVhLogUrl(parseWebVh(`did:webvh:${SCID}:${location}`));

afterEach(() => {
  restoreFetch();
});

describe('DID から HTTPS URL への変換', () => {
  it.each([
    ['example.com', 'https://example.com/.well-known/did.jsonl'],
    ['issuer.example.com', 'https://issuer.example.com/.well-known/did.jsonl'],
    ['example.com:dids:issuer', 'https://example.com/dids/issuer/did.jsonl'],
    ['example.com%3A3000:dids:issuer', 'https://example.com:3000/dids/issuer/did.jsonl'],
    ['example.com%3A3000', 'https://example.com:3000/.well-known/did.jsonl'],
    // 仕様の例（国際化ドメイン名）。DID 文字列は DID Core の idchar しか使えないので UTF-8 をパーセントエンコードして書く。
    [
      'jp%E7%B4%8D%E8%B1%86.%E4%BE%8B.jp:%E7%94%A8%E6%88%B7',
      'https://xn--jp-cd2fp15c.xn--fsq.jp/%E7%94%A8%E6%88%B7/did.jsonl',
    ],
  ])('%s → %s（spec 例）', (location, url) => {
    expect(urlOf(location)).toBe(url);
  });

  it('大文字のドメインは小文字へ、path はデコードして RFC 3986 に従い再エンコードする', () => {
    expect(urlOf('Example.COM:a%2Eb:%7Euser')).toBe('https://example.com/a.b/~user/did.jsonl');
  });

  it('witness proof ファイルの URL は DID Log の URL の末尾 did.jsonl を did-witness.json に替えたもの', () => {
    const parsed = parseWebVh(`did:webvh:${SCID}:example.com%3A8443:dids:issuer`);
    expect(webVhWitnessUrl(parsed)).toBe('https://example.com:8443/dids/issuer/did-witness.json');
    expect(webVhWitnessUrl(parseWebVh(`did:webvh:${SCID}:example.com`))).toBe(
      'https://example.com/.well-known/did-witness.json',
    );
  });
});

describe('拒否する DID（公式テストスイートの negative-* と同じ観点）', () => {
  it.each([
    // IP リテラル（10 進・パーセントエンコード・16 進・整数・IPv6）。
    '127.0.0.1',
    '127%2E0%2E0%2E1',
    '127%2e0%2e0%2e1',
    '169%2E254%2E169%2E254',
    '0x7f.0.0.1',
    '2130706433',
    '[::1]',
    // パーセントエンコードされた区切り・構造文字。
    'example.com%2Fevil',
    'example.com%3Fx',
    'example.com%23x',
    'example.com%40evil.example',
    'user%40example.com',
    'example%3A.com',
    // ポート。
    'example.com%3A0',
    'example.com%3A65536',
    'example.com%3A8080%3A9090',
    'example.com%3A',
    // ラベル・長さ。
    'example..com',
    '-example.com',
    'example-.com',
    `${'a'.repeat(64)}.com`,
    'localhost',
    // 不正なパーセントエンコード・生の Unicode・空白。
    'example.com%',
    'example.com%ZZ',
    '納豆.jp',
    'exa mple.com',
    'example.com%20',
  ])('domain %s は拒否する', (domain) => {
    expect(() => urlOf(domain)).toThrow(INVALID_DID);
  });

  it.each([
    '..',
    '.',
    '%2e%2e',
    '%2E%2E',
    '%2e',
    'a%2Fb',
    'a%5Cb',
    'a%00b',
    '%20a',
    'a%20',
    'a%',
    'a b',
    'a?b',
    'a#b',
    'a/b',
    '用户',
  ])('path セグメント %s は拒否する', (segment) => {
    expect(() => urlOf(`example.com:${segment}`)).toThrow(INVALID_DID);
  });

  it('SCID が base58btc の 46 文字でない DID は拒否する', () => {
    for (const scid of [
      '',
      'Qm',
      `Qm${'S'.repeat(43)}`,
      `Qm${'S'.repeat(45)}`,
      `Qm${'0'.repeat(44)}`,
    ]) {
      expect(() => parseWebVh(`did:webvh:${scid}:example.com`)).toThrow(INVALID_DID);
    }
  });
});

describe('Content-Type', () => {
  function respondWith(contentType: string | null, body = '{}\n') {
    globalThis.fetch = (async () =>
      new Response(body, {
        status: 200,
        headers: contentType === null ? {} : { 'content-type': contentType },
      })) as unknown as typeof fetch;
  }

  it.each([
    'text/jsonl',
    'text/jsonl; charset=utf-8',
    'application/jsonl',
    'text/plain',
  ])('DID Log は %s を受理する（仕様は text/jsonl を推奨）', async (contentType) => {
    respondWith(contentType);
    expect(await fetchDidLog('https://example.com/.well-known/did.jsonl')).toBe('{}\n');
  });

  it.each([
    'application/json',
    'text/html',
    null,
  ])('DID Log は %p を受理しない', async (contentType) => {
    respondWith(contentType);
    await expect(fetchDidLog('https://example.com/.well-known/did.jsonl')).rejects.toMatchObject({
      code: '2003',
    });
  });

  it('did-witness.json は application/json だけを受理し、Accept でもそれを要求する', async () => {
    let accept: string | undefined;
    globalThis.fetch = (async (_url: string, init?: RequestInit) => {
      accept = (init?.headers as Record<string, string>).Accept;
      return new Response('[]', { status: 200, headers: { 'content-type': 'application/json' } });
    }) as unknown as typeof fetch;
    expect(
      await fetchDidLog(
        'https://example.com/.well-known/did-witness.json',
        undefined,
        undefined,
        DID_WITNESS_MEDIA_TYPES,
      ),
    ).toBe('[]');
    expect(accept).toBe('application/json');

    respondWith('text/plain', '[]');
    await expect(
      fetchDidLog(
        'https://example.com/.well-known/did-witness.json',
        undefined,
        undefined,
        DID_WITNESS_MEDIA_TYPES,
      ),
    ).rejects.toMatchObject({
      code: '2003',
    });
  });
});
