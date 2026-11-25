/**
 * Federation Entity Statement キャッシュ層: negative cache・利用者設定・キャッシュキー・エラー衛生。
 *
 * 検証内容: negative cache の対象境界（取得失敗 5011 のみ記憶し、検証失敗 5010 は記憶しない）、
 * 利用者設定の緩和拒否（3002）と厳格化の採用、Subordinate Statement のキャッシュキーが `sub` を
 * 含むこと、エラー衛生。TTL 算出と取得経路は
 * `ttl-and-entity-configuration.test.ts`。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes } from '../../../../errors.js';
import {
  resolveEntityConfiguration,
  verifyEntityConfiguration,
} from '../../entity-configuration.js';
import type { JsonWebKeySet } from '../../federation-types.js';
import { verifySubordinate } from '../../subordinate.js';
import {
  ANCHOR_KEY,
  INTERMEDIATE_KEY,
  LEAF_KEY,
  NOW_SECONDS,
  signStatement,
  toJwk,
  validPeriod,
  WRONG_KEY,
} from '../federation-fixtures.js';
import {
  ENTITY_ID,
  expectRejectCode,
  harness,
  selfSigned,
  WELL_KNOWN,
  YEAR_SECONDS,
} from './harness.js';

describe('negative cache と利用者設定', () => {
  it('取得失敗（5011）は 30 秒記憶し、経過後は再取得する', async () => {
    const h = harness(() => undefined);

    await expectRejectCode(
      resolveEntityConfiguration(ENTITY_ID, h.deps),
      ErrorCodes.FEDERATION_FETCH_FAILED,
    );
    h.advance(29);
    await expectRejectCode(
      resolveEntityConfiguration(ENTITY_ID, h.deps),
      ErrorCodes.FEDERATION_FETCH_FAILED,
    );
    expect(h.count()).toBe(1);
    expect(h.events.map((e) => e.state)).toEqual(['cold', 'hot']);

    h.advance(2);
    await expectRejectCode(
      resolveEntityConfiguration(ENTITY_ID, h.deps),
      ErrorCodes.FEDERATION_FETCH_FAILED,
    );
    expect(h.count()).toBe(2);
  });

  it('検証失敗（5010）は記憶せず、次回もネットワークに出る', async () => {
    // 取得は成功するが署名が別鍵で成立しない Statement。
    const bad = signStatement(
      WRONG_KEY,
      {
        iss: ENTITY_ID,
        sub: ENTITY_ID,
        ...validPeriod(),
        jwks: { keys: [toJwk(LEAF_KEY, 'leaf-1')] },
      },
      { kid: 'leaf-1' },
    );
    const h = harness((url) => (url === WELL_KNOWN ? bad : undefined));

    await expectRejectCode(
      resolveEntityConfiguration(ENTITY_ID, h.deps),
      ErrorCodes.TRUST_CHAIN_INVALID,
    );
    await expectRejectCode(
      resolveEntityConfiguration(ENTITY_ID, h.deps),
      ErrorCodes.TRUST_CHAIN_INVALID,
    );
    expect(h.count()).toBe(2);
  });

  it('上限を緩める maxTtlSeconds=601 は 3002 で拒否する', async () => {
    const jwt = selfSigned(NOW_SECONDS - 60, NOW_SECONDS + 120);
    const h = harness((url) => (url === WELL_KNOWN ? jwt : undefined));

    await expectRejectCode(
      resolveEntityConfiguration(ENTITY_ID, { ...h.deps, maxTtlSeconds: 601 }),
      ErrorCodes.VC_SCHEMA_INVALID,
    );
    expect(h.count()).toBe(0);
  });

  it('厳しくする maxTtlSeconds=300 は採用され、301 秒後に再取得する', async () => {
    const jwt = selfSigned(NOW_SECONDS - 60, NOW_SECONDS + YEAR_SECONDS);
    const h = harness((url) => (url === WELL_KNOWN ? jwt : undefined));
    const deps = { ...h.deps, maxTtlSeconds: 300 };

    await resolveEntityConfiguration(ENTITY_ID, deps);
    h.advance(299);
    await resolveEntityConfiguration(ENTITY_ID, deps);
    expect(h.count()).toBe(1);

    h.advance(2);
    await resolveEntityConfiguration(ENTITY_ID, deps);
    expect(h.count()).toBe(2);
  });
});

describe('Subordinate Statement のキャッシュキー', () => {
  const PARENT_ID = 'https://anchor.example.eu';
  const PARENT_FETCH = `${PARENT_ID}/fetch`;
  const CHILD_A = 'https://a.example.eu';
  const CHILD_B = 'https://b.example.eu';
  const jwksA: JsonWebKeySet = { keys: [toJwk(LEAF_KEY, 'a-1')] };
  const jwksB: JsonWebKeySet = { keys: [toJwk(INTERMEDIATE_KEY, 'b-1')] };

  /** 親の検証済み Entity Configuration（fetch endpoint を持つ）。 */
  function parentConfig() {
    const jwt = signStatement(
      ANCHOR_KEY,
      {
        iss: PARENT_ID,
        sub: PARENT_ID,
        ...validPeriod(),
        jwks: { keys: [toJwk(ANCHOR_KEY, 'anchor-1')] },
        metadata: { federation_entity: { federation_fetch_endpoint: PARENT_FETCH } },
      },
      { kid: 'anchor-1' },
    );
    return verifyEntityConfiguration(PARENT_ID, jwt, NOW_SECONDS);
  }

  /** 親が child について発行する Subordinate Statement。 */
  function subordinateFor(child: string, jwks: JsonWebKeySet): string {
    return signStatement(ANCHOR_KEY, { iss: PARENT_ID, sub: child, ...validPeriod(), jwks });
  }

  it('sub が異なれば同一 endpoint でもキャッシュを共有しない', async () => {
    const bodies = new Map([
      [`${PARENT_FETCH}?sub=${encodeURIComponent(CHILD_A)}`, subordinateFor(CHILD_A, jwksA)],
      [`${PARENT_FETCH}?sub=${encodeURIComponent(CHILD_B)}`, subordinateFor(CHILD_B, jwksB)],
    ]);
    const h = harness((url) => bodies.get(url));
    const parent = parentConfig();

    const a = await verifySubordinate(parent, CHILD_A, jwksA, NOW_SECONDS, h.deps);
    const b = await verifySubordinate(parent, CHILD_B, jwksB, NOW_SECONDS, h.deps);
    expect(h.count()).toBe(2);
    expect(a.statement.sub).toBe(CHILD_A);
    expect(b.statement.sub).toBe(CHILD_B);

    // 同一 sub の 2 回目はキャッシュ命中（取得は増えない）。
    const again = await verifySubordinate(parent, CHILD_A, jwksA, NOW_SECONDS, h.deps);
    expect(h.count()).toBe(2);
    expect(again.statement.sub).toBe(CHILD_A);
    expect(h.events.map((e) => e.state)).toEqual(['cold', 'cold', 'hot']);
    expect(h.events.every((e) => e.kind === 'subordinate-statement')).toBe(true);
  });
});

describe('エラー衛生', () => {
  it('例外・context・観測イベントに entity_id / URL / JWT を載せない', async () => {
    const h = harness(() => undefined);
    const failure = await expectRejectCode(
      resolveEntityConfiguration(ENTITY_ID, h.deps),
      ErrorCodes.FEDERATION_FETCH_FAILED,
    );

    const serialized = `${failure.message} ${JSON.stringify(failure.context ?? {})}`;
    expect(serialized).not.toContain(ENTITY_ID);
    expect(serialized).not.toContain(WELL_KNOWN);
    for (const event of h.events) {
      expect(Object.keys(event).sort()).toEqual(['kind', 'state']);
    }
  });
});
