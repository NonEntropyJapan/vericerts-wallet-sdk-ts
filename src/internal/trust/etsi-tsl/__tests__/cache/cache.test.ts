import { describe, expect, test } from 'bun:test';
import {
  buildTrustedListCacheEntry,
  createTrustedListCache,
  readTrustedListCache,
  storeTrustedListCache,
} from '../../cache.js';

const NOW_SECONDS = 1_700_000_000;
const NOW_ISO = new Date(NOW_SECONDS * 1000).toISOString();

function tslXmlWithNextUpdate(nextUpdateIso: string): string {
  return (
    '<TrustServiceStatusList><SchemeInformation><NextUpdate>' +
    `<dateTime>${nextUpdateIso}</dateTime>` +
    '</NextUpdate></SchemeInformation></TrustServiceStatusList>'
  );
}

describe('buildTrustedListCacheEntry', () => {
  test('XML の NextUpdate を nextUpdate に採用する', () => {
    const nextUpdateIso = new Date((NOW_SECONDS + 3600) * 1000).toISOString();
    const entry = buildTrustedListCacheEntry({
      url: 'https://tsl.example/DE.xml',
      type: 'tsl',
      country: 'DE',
      xml: tslXmlWithNextUpdate(nextUpdateIso),
      signatureValid: true,
      fetchedAt: NOW_ISO,
    });
    expect(entry.nextUpdate).toBe(nextUpdateIso);
    expect(entry.url).toBe('https://tsl.example/DE.xml');
    expect(entry.type).toBe('tsl');
    expect(entry.country).toBe('DE');
    expect(entry.signatureValid).toBe(true);
    expect(entry.fetchedAt).toBe(NOW_ISO);
  });

  test('NextUpdate を抽出できない場合は fetchedAt を採用する（即時失効扱い）', () => {
    const entry = buildTrustedListCacheEntry({
      url: 'https://lotl.example/lotl.xml',
      type: 'lotl',
      xml: '<TrustServiceStatusList><SchemeInformation></SchemeInformation></TrustServiceStatusList>',
      signatureValid: true,
      fetchedAt: NOW_ISO,
    });
    expect(entry.nextUpdate).toBe(NOW_ISO);
    expect(entry.country).toBeUndefined();
  });
});

describe('storeTrustedListCache / readTrustedListCache', () => {
  test('nextUpdate 内なら読み出せる', () => {
    const cache = createTrustedListCache(() => NOW_SECONDS);
    const nextUpdateIso = new Date((NOW_SECONDS + 3600) * 1000).toISOString();
    const entry = buildTrustedListCacheEntry({
      url: 'https://tsl.example/DE.xml',
      type: 'tsl',
      country: 'DE',
      xml: tslXmlWithNextUpdate(nextUpdateIso),
      signatureValid: true,
      fetchedAt: NOW_ISO,
    });

    storeTrustedListCache(cache, entry, NOW_SECONDS);
    expect(readTrustedListCache(cache, entry.url, NOW_SECONDS)).toEqual(entry);
  });

  test('nextUpdate を過ぎていれば読み出せない', () => {
    const cache = createTrustedListCache(() => NOW_SECONDS);
    const pastNextUpdate = new Date((NOW_SECONDS - 3600) * 1000).toISOString();
    const entry = buildTrustedListCacheEntry({
      url: 'https://tsl.example/DE.xml',
      type: 'tsl',
      country: 'DE',
      xml: tslXmlWithNextUpdate(pastNextUpdate),
      signatureValid: true,
      fetchedAt: NOW_ISO,
    });

    storeTrustedListCache(cache, entry, NOW_SECONDS);
    expect(readTrustedListCache(cache, entry.url, NOW_SECONDS)).toBeUndefined();
  });

  test('nextUpdate ちょうど(境界)は失効扱いになる(FO-5 対象外)', () => {
    // `ttl-cache.ts` の失効判定は `now >= expiresAtSeconds` で境界を失効側に含める。
    // ここでは `nextUpdate` そのものを `now` として与え、ちょうど到達した瞬間は
    // 「まだ有効期限内」ではなく「失効済み」（FO-5 の対象外）として扱われることを固定する。
    const cache = createTrustedListCache(() => NOW_SECONDS);
    const nextUpdateSeconds = NOW_SECONDS + 3600;
    const nextUpdateIso = new Date(nextUpdateSeconds * 1000).toISOString();
    const entry = buildTrustedListCacheEntry({
      url: 'https://tsl.example/DE.xml',
      type: 'tsl',
      country: 'DE',
      xml: tslXmlWithNextUpdate(nextUpdateIso),
      signatureValid: true,
      fetchedAt: NOW_ISO,
    });

    storeTrustedListCache(cache, entry, NOW_SECONDS);
    expect(readTrustedListCache(cache, entry.url, nextUpdateSeconds - 1)).toEqual(entry);
    expect(readTrustedListCache(cache, entry.url, nextUpdateSeconds)).toBeUndefined();
  });

  test('未格納の URL は undefined を返す', () => {
    const cache = createTrustedListCache(() => NOW_SECONDS);
    expect(
      readTrustedListCache(cache, 'https://unknown.example/tsl.xml', NOW_SECONDS),
    ).toBeUndefined();
  });

  test('nextUpdate が抽出不能（fetchedAt 採用）だと TTL 0 で即時失効する', () => {
    const cache = createTrustedListCache(() => NOW_SECONDS);
    const entry = buildTrustedListCacheEntry({
      url: 'https://lotl.example/lotl.xml',
      type: 'lotl',
      xml: '<TrustServiceStatusList></TrustServiceStatusList>',
      signatureValid: true,
      fetchedAt: NOW_ISO,
    });

    storeTrustedListCache(cache, entry, NOW_SECONDS);
    expect(readTrustedListCache(cache, entry.url, NOW_SECONDS)).toBeUndefined();
  });
});
