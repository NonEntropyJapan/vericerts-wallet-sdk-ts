/**
 * 期限・鮮度判定がオフセット無し / 非 ISO の日時を TZ 依存で解釈しないこと。
 *
 * ETSI TSL キャッシュ・Federation entity cache・WUA 期限判定・format-negotiation の鮮度/履歴比較が
 * `Date.parse` 単独だと、`2026-10-02T00:00:00`（オフセット無し）が実行 TZ のローカル時刻として解釈され、
 * TZ により合否や TTL が変わる。共有パーサ（`parseIsoDateTimeMs`）経由で NaN に倒し fail-closed にする。
 */

import { afterEach, describe, expect, it } from 'bun:test';
import { compareCandidates } from '../../credential/format-negotiation/compare.js';
import { freshnessScore } from '../../credential/format-negotiation/scoring.js';
import type { NegotiableCredential } from '../../credential/format-negotiation/types.js';
import { createFormatWorkBudget } from '../../credential/format-negotiation/work.js';
import type { WalletUnitAttestation } from '../../eudi/wua/types.js';
import { isWalletAttestationExpired } from '../../eudi/wua/wua.js';
import { nextVersionTime } from '../../identity/webvh/codec.js';
import {
  createTrustedListCache,
  readTrustedListCache,
  storeTrustedListCache,
  type TrustedListCache,
} from '../../trust/etsi-tsl/cache.js';
import {
  type FederationEntityCache,
  federationEntityCacheTtlSeconds,
} from '../../trust/federation/cache/entity-cache.js';

const ORIGINAL_TZ = process.env.TZ;
const TIME_ZONES = ['UTC', 'Pacific/Kiritimati', 'America/Los_Angeles'] as const;
const NOW_SECONDS = Date.UTC(2026, 5, 1) / 1000;

afterEach(() => {
  if (ORIGINAL_TZ === undefined) {
    delete process.env.TZ;
  } else {
    process.env.TZ = ORIGINAL_TZ;
  }
});

function acrossTimeZones<T>(fn: () => T): T[] {
  return TIME_ZONES.map((tz) => {
    process.env.TZ = tz;
    return fn();
  });
}

describe('ETSI TSL キャッシュの nextUpdate', () => {
  const entry = (nextUpdate: string): TrustedListCache => ({
    url: 'https://tsl.example/de.xml',
    type: 'tsl',
    xml: '<x/>',
    signatureValid: true,
    nextUpdate,
    fetchedAt: '2026-06-01T00:00:00Z',
  });

  it('オフセット無し nextUpdate は TZ に依らず格納されない（再利用されない）', () => {
    const hits = acrossTimeZones(() => {
      const cache = createTrustedListCache(() => NOW_SECONDS);
      storeTrustedListCache(cache, entry('2026-06-01T01:00:00'), NOW_SECONDS);
      return readTrustedListCache(cache, 'https://tsl.example/de.xml', NOW_SECONDS) !== undefined;
    });
    expect(hits).toEqual([false, false, false]);
  });

  it('オフセット付き nextUpdate は TZ に依らず格納され、期限後は未命中', () => {
    const results = acrossTimeZones(() => {
      const cache = createTrustedListCache(() => NOW_SECONDS);
      storeTrustedListCache(cache, entry('2026-06-01T01:00:00Z'), NOW_SECONDS);
      const url = 'https://tsl.example/de.xml';
      return [
        readTrustedListCache(cache, url, NOW_SECONDS + 1800) !== undefined,
        readTrustedListCache(cache, url, NOW_SECONDS + 7200) !== undefined,
      ];
    });
    expect(results).toEqual([
      [true, false],
      [true, false],
      [true, false],
    ]);
  });
});

describe('federationEntityCacheTtlSeconds', () => {
  const cached = (expiresAt: string) => ({ expiresAt }) as FederationEntityCache;

  it('不正・オフセット無しの expiresAt は NaN ではなく TTL 0', () => {
    for (const bad of ['not-a-date', '2026-06-01T01:00:00', 'Dec 1 2099', '']) {
      const ttls = acrossTimeZones(() => federationEntityCacheTtlSeconds(cached(bad), NOW_SECONDS));
      expect(ttls).toEqual([0, 0, 0]);
    }
  });

  it('非有限の nowSeconds も TTL 0', () => {
    expect(federationEntityCacheTtlSeconds(cached('2099-01-01T00:00:00Z'), Number.NaN)).toBe(0);
  });

  it('オフセット付きは TZ に依らず残り秒数', () => {
    const ttls = acrossTimeZones(() =>
      federationEntityCacheTtlSeconds(cached('2026-06-01T01:00:00Z'), NOW_SECONDS),
    );
    expect(ttls).toEqual([3600, 3600, 3600]);
  });
});

describe('isWalletAttestationExpired', () => {
  const wua = (expiresAt: string) => ({ expiresAt }) as WalletUnitAttestation;

  it('オフセット無し・非 ISO の expiresAt は TZ に依らず期限切れ', () => {
    for (const bad of ['2099-01-01T00:00:00', 'Dec 1 2099', '2099']) {
      expect(acrossTimeZones(() => isWalletAttestationExpired(wua(bad), NOW_SECONDS))).toEqual([
        true,
        true,
        true,
      ]);
    }
    expect(isWalletAttestationExpired(wua('2099-01-01T00:00:00Z'), NOW_SECONDS)).toBe(false);
  });
});

describe('format-negotiation の日時', () => {
  const vc = (o: Partial<NegotiableCredential>): NegotiableCredential =>
    ({ id: 'a', format: 'vc+sd-jwt', alg: 'ES256', ...o }) as NegotiableCredential;

  it('freshnessScore はオフセット無し・非 ISO を 0 に倒す', () => {
    for (const bad of ['2099-01-01T00:00:00', 'Dec 1 2099', '2099']) {
      expect(acrossTimeZones(() => freshnessScore(bad))).toEqual([0, 0, 0]);
    }
    expect(freshnessScore('2099-01-01T00:00:00Z')).toBe(Date.UTC(2099, 0, 1));
  });

  it('lastUsedAt / issuanceDate のオフセット無しは「無し」扱いで有効な方が優先される', () => {
    const request = { 'vc+sd-jwt': { alg: ['ES256'] } };
    for (const field of ['lastUsedAt', 'issuanceDate'] as const) {
      const bad = vc({ id: 'bad', [field]: '2099-01-01T00:00:00' });
      const good = vc({ id: 'good', [field]: '2026-01-01T00:00:00Z' });
      const results = acrossTimeZones(() =>
        compareCandidates(bad, good, request, createFormatWorkBudget()),
      );
      expect(results.every((r) => r > 0)).toBe(true);
    }
  });
});

describe('nextVersionTime', () => {
  it('オフセット無しの前版は TZ 依存の加算をせず現在時刻を返す', () => {
    const before = Date.now();
    for (const ms of acrossTimeZones(() => Date.parse(nextVersionTime('2099-01-01T00:00:00')))) {
      expect(ms).toBeGreaterThanOrEqual(before);
      expect(ms).toBeLessThan(Date.UTC(2098, 0, 1));
    }
  });
});
