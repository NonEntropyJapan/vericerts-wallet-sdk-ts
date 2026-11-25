/**
 * 本文文字列を保持する TTL キャッシュ（Status List Token / TSL XML）の総量上限。
 * 件数 256 だけでは 1 MiB × 256 件を保持できるため、本文長を重みに計上して総量でも追い出す。
 */

import { describe, expect, it } from 'bun:test';
import { cacheFetchedToken, createStatusListCache } from '../../issuer/status-list-cache.js';
import {
  createTrustedListCache,
  readTrustedListCache,
  storeTrustedListCache,
} from '../../trust/etsi-tsl/cache.js';
import { STRING_CACHE_MAX_TOTAL_LENGTH } from '../ttl-cache.js';

const MIB = 1024 * 1024;

describe('総量上限（STRING_CACHE_MAX_TOTAL_LENGTH）', () => {
  it('Status List Token: 1 MiB × 256 件を投入しても保持は総量上限（32 件）に収まる', () => {
    const cache = createStatusListCache(() => 0);
    const token = 'x'.repeat(MIB);
    for (let i = 0; i < 256; i++) {
      cacheFetchedToken({
        cache,
        uri: `https://issuer.example/status/${i}`,
        token,
        cacheControl: 'max-age=60',
        maxTtlSeconds: 60,
        nowSeconds: 0,
      });
    }
    expect(cache.size).toBe(STRING_CACHE_MAX_TOTAL_LENGTH / MIB);
    // 古い順に追い出され、直近の分が残る。
    expect(cache.get('https://issuer.example/status/0', 0)).toBeUndefined();
    expect(cache.get('https://issuer.example/status/255', 0)).toBeDefined();
  });

  it('Status List Token: 通常サイズの Token は件数上限（256）まで保持される', () => {
    const cache = createStatusListCache(() => 0);
    for (let i = 0; i < 300; i++) {
      cacheFetchedToken({
        cache,
        uri: `https://issuer.example/status/${i}`,
        token: 'x'.repeat(1000),
        cacheControl: 'max-age=60',
        maxTtlSeconds: 60,
        nowSeconds: 0,
      });
    }
    expect(cache.size).toBe(256);
  });

  it('TSL: XML 本文長が総量上限を超えるエントリは格納しない', () => {
    const cache = createTrustedListCache(() => 0);
    const entry = (url: string, xml: string) => ({
      url,
      type: 'tsl' as const,
      xml,
      signatureValid: true,
      nextUpdate: '1970-01-02T00:00:00Z',
      fetchedAt: '1970-01-01T00:00:00Z',
    });
    storeTrustedListCache(cache, entry('https://tsl.example/ok', 'x'.repeat(1000)), 0);
    storeTrustedListCache(
      cache,
      entry('https://tsl.example/huge', 'x'.repeat(STRING_CACHE_MAX_TOTAL_LENGTH + 1)),
      0,
    );
    expect(readTrustedListCache(cache, 'https://tsl.example/ok', 0)).toBeDefined();
    expect(readTrustedListCache(cache, 'https://tsl.example/huge', 0)).toBeUndefined();
  });
});
