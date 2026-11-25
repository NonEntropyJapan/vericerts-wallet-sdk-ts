/**
 * Federation Entity Statement キャッシュ層: TTL 算出と Entity Configuration の取得経路。
 *
 * 検証内容: TTL が `min(exp - now, 600)` であること（`exp` 準拠 + 鍵無効化宣言の伝播 SLA での
 * 頭打ち）、cold / warm / hot の遷移、キャッシュ命中時も再検証すること、キャッシュ未注入時の
 * 後方互換。negative cache・利用者設定・キャッシュキーは `negative-cache-and-keys.test.ts`。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes } from '../../../../errors.js';
import {
  FEDERATION_CACHE_MAX_TTL_SECONDS,
  statementCacheTtlSeconds,
} from '../../cache/statement-cache.js';
import { resolveEntityConfiguration } from '../../entity-configuration.js';
import { NOW_SECONDS } from '../federation-fixtures.js';
import {
  countingFetch,
  ENTITY_ID,
  expectRejectCode,
  harness,
  selfSigned,
  WELL_KNOWN,
  YEAR_SECONDS,
} from './harness.js';

/** 既定上限での TTL 算出（上界を決めるのは `exp` のみ）。 */
function ttl(exp: number): number {
  return statementCacheTtlSeconds(
    { iat: NOW_SECONDS - 600, exp },
    NOW_SECONDS,
    FEDERATION_CACHE_MAX_TTL_SECONDS,
  );
}

describe('statementCacheTtlSeconds', () => {
  it('600 秒に収まる exp では exp - now をそのまま採用する（独自短縮なし）', () => {
    expect(ttl(NOW_SECONDS + 120)).toBe(120);
  });

  it('exp が 600 秒を大きく超えても伝播 SLA の 600 秒で頭打ちにする', () => {
    expect(FEDERATION_CACHE_MAX_TTL_SECONDS).toBe(600);
    expect(ttl(NOW_SECONDS + YEAR_SECONDS)).toBe(600);
  });

  it('失効済み（exp < now）は 0 を返しキャッシュしない', () => {
    expect(ttl(NOW_SECONDS - 1)).toBe(0);
  });

  it('exp === now は 0 を返す（境界は失効側）', () => {
    expect(ttl(NOW_SECONDS)).toBe(0);
  });
});

describe('Entity Configuration のキャッシュ', () => {
  it('TTL 内の 2 回目は取得せずキャッシュから返す（cold → hot）', async () => {
    const jwt = selfSigned(NOW_SECONDS - 60, NOW_SECONDS + 120);
    const h = harness((url) => (url === WELL_KNOWN ? jwt : undefined));

    const first = await resolveEntityConfiguration(ENTITY_ID, h.deps);
    h.advance(60);
    const second = await resolveEntityConfiguration(ENTITY_ID, h.deps);

    expect(h.count()).toBe(1);
    expect(second.statement.sub).toBe(first.statement.sub);
    expect(h.events.map((e) => e.state)).toEqual(['cold', 'hot']);
    expect(h.events.every((e) => e.kind === 'entity-configuration')).toBe(true);
  });

  it('exp を過ぎたエントリは warm として再取得する', async () => {
    let jwt = selfSigned(NOW_SECONDS - 60, NOW_SECONDS + 120);
    const h = harness((url) => (url === WELL_KNOWN ? jwt : undefined));

    await resolveEntityConfiguration(ENTITY_ID, h.deps);
    h.advance(130);
    jwt = selfSigned(NOW_SECONDS + 130, NOW_SECONDS + 250);
    await resolveEntityConfiguration(ENTITY_ID, h.deps);

    expect(h.count()).toBe(2);
    expect(h.events.map((e) => e.state)).toEqual(['cold', 'warm']);
  });

  it('exp が 1 年先でも 601 秒後には再取得する（鍵無効化宣言の伝播 600 秒保証）', async () => {
    const jwt = selfSigned(NOW_SECONDS - 60, NOW_SECONDS + YEAR_SECONDS);
    const h = harness((url) => (url === WELL_KNOWN ? jwt : undefined));

    await resolveEntityConfiguration(ENTITY_ID, h.deps);
    h.advance(599);
    await resolveEntityConfiguration(ENTITY_ID, h.deps);
    expect(h.count()).toBe(1);

    h.advance(2);
    await resolveEntityConfiguration(ENTITY_ID, h.deps);
    expect(h.count()).toBe(2);
    expect(h.events.map((e) => e.state)).toEqual(['cold', 'hot', 'warm']);
  });

  it('キャッシュ命中時も再検証し、失効済み JWT を有効として返さない', async () => {
    const expired = selfSigned(NOW_SECONDS - 600, NOW_SECONDS - 1);
    const h = harness(() => undefined);
    // TTL は残っているが Statement 自身は失効している状態を作る。
    h.statementCache.set(WELL_KNOWN, expired, 600, NOW_SECONDS);

    await expectRejectCode(
      resolveEntityConfiguration(ENTITY_ID, h.deps),
      ErrorCodes.TRUST_CHAIN_INVALID,
    );
    // ネットワークには出ていない（hot 経路）が、検証は素通りしていない。
    expect(h.count()).toBe(0);
    expect(h.events.map((e) => e.state)).toEqual(['hot']);
  });

  it('キャッシュ未注入なら従来どおり毎回取得する（後方互換）', async () => {
    const jwt = selfSigned(NOW_SECONDS - 60, NOW_SECONDS + 120);
    const { fetchFn, count } = countingFetch((url) => (url === WELL_KNOWN ? jwt : undefined));
    const deps = { fetchFn, now: (): number => NOW_SECONDS * 1000 };

    await resolveEntityConfiguration(ENTITY_ID, deps);
    await resolveEntityConfiguration(ENTITY_ID, deps);
    expect(count()).toBe(2);
  });
});
