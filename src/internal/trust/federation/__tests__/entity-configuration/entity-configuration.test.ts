/**
 * resolveEntityConfiguration / verifyEntityConfiguration / entityConfigurationUrl の
 * ユニットテスト。実鍵 P-256 で署名、`fetch` はモック。
 *
 * 検証内容:
 * - well-known URL 変換（ドメインのみ / パスあり / 末尾スラッシュ / 非 HTTPS 拒否）。
 * - 正常系: 自己署名 Entity Configuration の取得・検証成功。
 * - 取得失敗（HTTP 4xx / 非 HTTPS リダイレクト / ネットワークエラー）→ FEDERATION_FETCH_FAILED（5011）。
 * - 検証失敗（署名不成立 / iss≠sub / entityId 不一致 / 期限切れ / alg=none）→ TRUST_CHAIN_INVALID（5010）。
 */

import { describe, expect, it } from 'bun:test';
import { type ErrorCode, ErrorCodes, VericertsError } from '../../../../errors.js';
import { createInMemoryMetrics, MetricNames } from '../../../../observability/metrics.js';
import { entityConfigurationUrl, resolveEntityConfiguration } from '../../entity-configuration.js';
import {
  LEAF_KEY,
  NOW_SECONDS,
  nowFn,
  signStatement,
  toJwk,
  validPeriod,
  WRONG_KEY,
} from '../federation-fixtures.js';

const ENTITY_ID = 'https://leaf.example.eu';
const WELL_KNOWN = `${ENTITY_ID}/.well-known/openid-federation`;

/** reject が指定コードの VericertsError であることを検証する。 */
async function expectRejectCode(promise: Promise<unknown>, code: ErrorCode): Promise<void> {
  let caught: unknown;
  try {
    await promise;
  } catch (error) {
    caught = error;
  }
  expect(caught).toBeInstanceOf(VericertsError);
  expect((caught as VericertsError).code).toBe(code);
}

/** 単一 URL に JWT を返す fetch モックを生成する（それ以外は 404）。 */
function singleResponse(
  url: string,
  jwt: string,
  contentType = 'application/entity-statement+jwt',
) {
  return (async (input: string | URL): Promise<Response> => {
    const requested = typeof input === 'string' ? input : input.toString();
    if (requested === url) {
      return new Response(jwt, { status: 200, headers: { 'content-type': contentType } });
    }
    return new Response('nf', { status: 404 });
  }) as typeof fetch;
}

/** 有効な自己署名 Entity Configuration を組み立てる。 */
function validSelfSigned(): string {
  return signStatement(
    LEAF_KEY,
    {
      iss: ENTITY_ID,
      sub: ENTITY_ID,
      ...validPeriod(),
      jwks: { keys: [toJwk(LEAF_KEY, 'leaf-1')] },
    },
    { kid: 'leaf-1' },
  );
}

describe('entityConfigurationUrl', () => {
  it('ドメインのみに well-known パスを付加する', () => {
    expect(entityConfigurationUrl('https://issuer.example.eu')).toBe(
      'https://issuer.example.eu/.well-known/openid-federation',
    );
  });

  it('パスありの末尾に well-known パスを付加する', () => {
    expect(entityConfigurationUrl('https://issuer.example.eu/tenant1')).toBe(
      'https://issuer.example.eu/tenant1/.well-known/openid-federation',
    );
  });

  it('末尾スラッシュを畳んでから付加する', () => {
    expect(entityConfigurationUrl('https://issuer.example.eu/')).toBe(
      'https://issuer.example.eu/.well-known/openid-federation',
    );
  });

  it('非 HTTPS は TRUST_CHAIN_INVALID', () => {
    expect(() => entityConfigurationUrl('http://issuer.example.eu')).toThrow(VericertsError);
    try {
      entityConfigurationUrl('http://issuer.example.eu');
    } catch (e) {
      expect((e as VericertsError).code).toBe(ErrorCodes.TRUST_CHAIN_INVALID);
    }
  });

  it('URL として不正な文字列は TRUST_CHAIN_INVALID', () => {
    try {
      entityConfigurationUrl('not a url');
    } catch (e) {
      expect((e as VericertsError).code).toBe(ErrorCodes.TRUST_CHAIN_INVALID);
    }
  });
});

describe('resolveEntityConfiguration - 正常系', () => {
  it('自己署名 Entity Configuration を取得・検証する', async () => {
    const jwt = validSelfSigned();
    const config = await resolveEntityConfiguration(ENTITY_ID, {
      fetchFn: singleResponse(WELL_KNOWN, jwt),
      now: nowFn,
    });
    expect(config.entityId).toBe(ENTITY_ID);
    expect(config.statement.iss).toBe(ENTITY_ID);
    expect(config.statement.sub).toBe(ENTITY_ID);
    expect(config.jwt).toBe(jwt);
    expect(config.statement.authority_hints).toBeUndefined();
  });

  it('Content-Type application/jwt も受理する', async () => {
    const jwt = validSelfSigned();
    const config = await resolveEntityConfiguration(ENTITY_ID, {
      fetchFn: singleResponse(WELL_KNOWN, jwt, 'application/jwt'),
      now: nowFn,
    });
    expect(config.statement.sub).toBe(ENTITY_ID);
  });
});

describe('resolveEntityConfiguration のメトリクス配線', () => {
  it('metrics 注入時、fetch_duration_seconds{kind=entity-configuration, cache=cold} を記録する', async () => {
    const { metrics, snapshot } = createInMemoryMetrics();
    await resolveEntityConfiguration(ENTITY_ID, {
      fetchFn: singleResponse(WELL_KNOWN, validSelfSigned()),
      now: nowFn,
      metrics,
    });
    const histogram = snapshot().histograms.find(
      (h) => h.name === MetricNames.FEDERATION_STATEMENT_FETCH_DURATION_SECONDS,
    );
    expect(histogram?.labels).toEqual({ kind: 'entity-configuration', cache: 'cold' });
    expect(histogram?.count).toBe(1);
  });

  it('metrics 未指定でも従来どおり動作する', async () => {
    const config = await resolveEntityConfiguration(ENTITY_ID, {
      fetchFn: singleResponse(WELL_KNOWN, validSelfSigned()),
      now: nowFn,
    });
    expect(config.statement.sub).toBe(ENTITY_ID);
  });
});

describe('resolveEntityConfiguration - 取得失敗（5011）', () => {
  it('HTTP 404 は FEDERATION_FETCH_FAILED', async () => {
    const fetchFn = (async (_input: string | URL) =>
      new Response('nf', { status: 404 })) as typeof fetch;
    await expectRejectCode(
      resolveEntityConfiguration(ENTITY_ID, { fetchFn, now: nowFn }),
      ErrorCodes.FEDERATION_FETCH_FAILED,
    );
  });

  it('ネットワークエラーは FEDERATION_FETCH_FAILED', async () => {
    const fetchFn = (async (_input: string | URL): Promise<Response> => {
      throw new Error('network down');
    }) as typeof fetch;
    await expectRejectCode(
      resolveEntityConfiguration(ENTITY_ID, { fetchFn, now: nowFn }),
      ErrorCodes.FEDERATION_FETCH_FAILED,
    );
  });

  it('非 HTTPS へのリダイレクト先は FEDERATION_FETCH_FAILED', async () => {
    const jwt = validSelfSigned();
    // Response.url は読み取り専用のため、http の最終 URL を持つ Response を defineProperty で構築する。
    const httpRedirect = (async (_input: string | URL) => {
      const r = new Response(jwt, {
        status: 200,
        headers: { 'content-type': 'application/jwt' },
      });
      Object.defineProperty(r, 'url', { value: 'http://evil.example/redirected' });
      return r;
    }) as typeof fetch;
    await expectRejectCode(
      resolveEntityConfiguration(ENTITY_ID, { fetchFn: httpRedirect, now: nowFn }),
      ErrorCodes.FEDERATION_FETCH_FAILED,
    );
  });

  it('空本文は FEDERATION_FETCH_FAILED', async () => {
    await expectRejectCode(
      resolveEntityConfiguration(ENTITY_ID, {
        fetchFn: singleResponse(WELL_KNOWN, ''),
        now: nowFn,
      }),
      ErrorCodes.FEDERATION_FETCH_FAILED,
    );
  });
});

describe('resolveEntityConfiguration - 検証失敗（5010）', () => {
  it('署名鍵不一致（別鍵で署名）は TRUST_CHAIN_INVALID', async () => {
    // payload の jwks は LEAF_KEY 由来だが、署名は WRONG_KEY で行う → 自己署名不成立。
    const jwt = signStatement(
      WRONG_KEY,
      {
        iss: ENTITY_ID,
        sub: ENTITY_ID,
        ...validPeriod(),
        jwks: { keys: [toJwk(LEAF_KEY, 'leaf-1')] },
      },
      { kid: 'leaf-1' },
    );
    await expectRejectCode(
      resolveEntityConfiguration(ENTITY_ID, {
        fetchFn: singleResponse(WELL_KNOWN, jwt),
        now: nowFn,
      }),
      ErrorCodes.TRUST_CHAIN_INVALID,
    );
  });

  it('iss ≠ sub は TRUST_CHAIN_INVALID', async () => {
    const jwt = signStatement(LEAF_KEY, {
      iss: ENTITY_ID,
      sub: 'https://other.example.eu',
      ...validPeriod(),
      jwks: { keys: [toJwk(LEAF_KEY)] },
    });
    await expectRejectCode(
      resolveEntityConfiguration(ENTITY_ID, {
        fetchFn: singleResponse(WELL_KNOWN, jwt),
        now: nowFn,
      }),
      ErrorCodes.TRUST_CHAIN_INVALID,
    );
  });

  it('entityId 引数と sub の不一致は TRUST_CHAIN_INVALID', async () => {
    const otherId = 'https://other.example.eu';
    const jwt = signStatement(LEAF_KEY, {
      iss: otherId,
      sub: otherId,
      ...validPeriod(),
      jwks: { keys: [toJwk(LEAF_KEY)] },
    });
    await expectRejectCode(
      // fetch は ENTITY_ID の well-known に対して otherId の EC を返す。
      resolveEntityConfiguration(ENTITY_ID, {
        fetchFn: singleResponse(WELL_KNOWN, jwt),
        now: nowFn,
      }),
      ErrorCodes.TRUST_CHAIN_INVALID,
    );
  });

  it('期限切れ（exp <= now）は TRUST_CHAIN_INVALID', async () => {
    const jwt = signStatement(LEAF_KEY, {
      iss: ENTITY_ID,
      sub: ENTITY_ID,
      iat: NOW_SECONDS - 7200,
      exp: NOW_SECONDS - 3600,
      jwks: { keys: [toJwk(LEAF_KEY)] },
    });
    await expectRejectCode(
      resolveEntityConfiguration(ENTITY_ID, {
        fetchFn: singleResponse(WELL_KNOWN, jwt),
        now: nowFn,
      }),
      ErrorCodes.TRUST_CHAIN_INVALID,
    );
  });

  it('alg=none は TRUST_CHAIN_INVALID', async () => {
    const header = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url');
    const payload = Buffer.from(
      JSON.stringify({
        iss: ENTITY_ID,
        sub: ENTITY_ID,
        ...validPeriod(),
        jwks: { keys: [toJwk(LEAF_KEY)] },
      }),
    ).toString('base64url');
    const jwt = `${header}.${payload}.`;
    await expectRejectCode(
      resolveEntityConfiguration(ENTITY_ID, {
        fetchFn: singleResponse(WELL_KNOWN, jwt),
        now: nowFn,
      }),
      ErrorCodes.TRUST_CHAIN_INVALID,
    );
  });

  it('jwks 欠落は TRUST_CHAIN_INVALID', async () => {
    const jwt = signStatement(LEAF_KEY, {
      iss: ENTITY_ID,
      sub: ENTITY_ID,
      ...validPeriod(),
    });
    await expectRejectCode(
      resolveEntityConfiguration(ENTITY_ID, {
        fetchFn: singleResponse(WELL_KNOWN, jwt),
        now: nowFn,
      }),
      ErrorCodes.TRUST_CHAIN_INVALID,
    );
  });
});
