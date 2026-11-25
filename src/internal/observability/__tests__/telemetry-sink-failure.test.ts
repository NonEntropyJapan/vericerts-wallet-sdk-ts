/**
 * 計装箇所全般のテレメトリ sink 失敗耐性。
 *
 * Metrics / Tracer が throw しても、本処理の成功結果と元のエラー（`VericertsError` のコード）を
 * 置換してはならない。
 */

import { describe, expect, it, setDefaultTimeout } from 'bun:test';
import {
  withOid4vpResponseMetrics,
  withPidIssuanceMetrics,
  withWuaRefreshMetrics,
} from '../../../wallet/eudi/observability.js';
import { postTokenRequest } from '../../auth/oid4vci/token/oid4vci-token-http.js';
import type { StatusListResolver } from '../../credential/sdjwt/status.js';
import { ErrorCodes, VericertsError } from '../../errors.js';
import {
  countStatusListChecks,
  instrumentStatusListFetch,
} from '../../issuer/status-list-observability.js';
import { KDF_TIMEOUT_MS } from '../../keymanager/__tests__/kdf-policy/kdf-timeout.js';
import type { KdfParams } from '../../keymanager/kdf.js';
import { MetricsInstrumentedKeyManager } from '../../keymanager/keymanager-metrics.js';
import { instrumentFederationStatementFetch } from '../../trust/federation/cache/statement-observability.js';
import { buildTrustChain } from '../../trust/federation/trust-chain.js';
import type { Metrics } from '../metrics.js';
import { type Span, type Tracer, traceSpan } from '../tracer.js';

/** 実 Argon2id を通るため、並列負荷下でも既定 5000ms で落ちないよう猶予を広げる。 */
setDefaultTimeout(KDF_TIMEOUT_MS);

const down = (): never => {
  throw new Error('sink down');
};
const throwingMetrics = { counter: down, histogram: down, gauge: down } as unknown as Metrics;

const throwingSpan: Span = {
  setAttribute: down,
  addEvent: down,
  recordException: down,
  setStatus: down,
  end: down,
};
const throwingTracer: Tracer = { startSpan: () => throwingSpan };
const startSpanThrows: Tracer = { startSpan: down };

describe('withXxxMetrics: Metrics sink が throw する場合', () => {
  const original = new VericertsError(ErrorCodes.DID_NOT_FOUND);
  const cases = [
    ['withPidIssuanceMetrics', withPidIssuanceMetrics],
    ['withWuaRefreshMetrics', withWuaRefreshMetrics],
    ['withOid4vpResponseMetrics', withOid4vpResponseMetrics],
  ] as const;
  for (const [name, wrap] of cases) {
    it(`${name}: 成功結果を置換しない`, async () => {
      await expect(wrap(throwingMetrics, async () => 'ISSUED')).resolves.toBe('ISSUED');
    });
    it(`${name}: 元のエラーを置換しない`, async () => {
      await expect(
        wrap(throwingMetrics, async () => {
          throw original;
        }),
      ).rejects.toBe(original);
    });
  }
});

describe('traceSpan: Tracer / Span が throw する場合', () => {
  const original = new VericertsError(ErrorCodes.DID_NOT_FOUND);
  for (const [label, tracer] of [
    ['Span 操作', throwingTracer],
    ['startSpan', startSpanThrows],
  ] as const) {
    it(`${label}の失敗で成功結果を置換しない`, async () => {
      await expect(traceSpan(tracer, 'x.op', 'x.result', async () => 'OK')).resolves.toBe('OK');
    });
    it(`${label}の失敗で元のエラーを置換しない`, async () => {
      await expect(
        traceSpan(tracer, 'x.op', 'x.result', async () => {
          throw original;
        }),
      ).rejects.toBe(original);
    });
  }
});

describe('MetricsInstrumentedKeyManager.encrypt: Metrics sink が throw する場合', () => {
  it('暗号化成功後に metrics が throw しても ciphertext を返す', async () => {
    const kdf: KdfParams = { algo: 'argon2id', version: 1, m: 9216, t: 4, p: 1 };
    const km = new MetricsInstrumentedKeyManager({ kdf }, throwingMetrics);
    const ciphertext = await km.encrypt(new Uint8Array([1, 2, 3]), 'pw');
    expect(ciphertext.length).toBeGreaterThan(3);
    await expect(km.decrypt(ciphertext, 'pw')).resolves.toEqual(new Uint8Array([1, 2, 3]));
  });
});

describe('countStatusListChecks / instrumentStatusListFetch: Metrics sink が throw する場合', () => {
  const ref = { status_list: { idx: 0, uri: 'https://issuer.example/status/1' } };
  it('判定結果を置換しない', async () => {
    const result = { valid: true, purpose: 'revocation', value: 0 };
    const resolver: StatusListResolver = { resolve: async () => result };
    await expect(countStatusListChecks(resolver, throwingMetrics).resolve(ref)).resolves.toBe(
      result,
    );
  });
  it('元のエラーを置換しない', async () => {
    const original = new VericertsError(ErrorCodes.TOKEN_STATUS_LIST_UNSUPPORTED);
    const resolver: StatusListResolver = {
      resolve: async () => {
        throw original;
      },
    };
    await expect(countStatusListChecks(resolver, throwingMetrics).resolve(ref)).rejects.toBe(
      original,
    );
  });
  it('取得結果 / 取得エラーを置換しない', async () => {
    const ok = instrumentStatusListFetch(throwingMetrics, {}, async () => 'TOKEN');
    await expect(ok.fetchToken('https://x')).resolves.toBe('TOKEN');
    const original = new Error('net');
    const ng = instrumentStatusListFetch(throwingMetrics, {}, async () => {
      throw original;
    });
    await expect(ng.fetchToken('https://x')).rejects.toBe(original);
    // hot 経路は観測フックから記録する。
    expect(() => ok.deps.onCacheEvent?.({ state: 'hot' } as never)).not.toThrow();
  });
});

describe('instrumentFederationStatementFetch: Metrics sink が throw する場合', () => {
  it('取得結果 / 取得エラーを置換しない', async () => {
    const base = {
      key: 'k',
      kind: 'entity-configuration',
      deps: {},
      nowSeconds: 0,
      verify: () => ({}),
    };
    const ok = instrumentFederationStatementFetch(throwingMetrics, {
      ...base,
      fetchJwt: async () => 'JWT',
    } as never);
    await expect(ok.fetchJwt()).resolves.toBe('JWT');
    const original = new VericertsError(ErrorCodes.FEDERATION_FETCH_FAILED);
    const ng = instrumentFederationStatementFetch(throwingMetrics, {
      ...base,
      fetchJwt: async () => {
        throw original;
      },
    } as never);
    await expect(ng.fetchJwt()).rejects.toBe(original);
  });
});

describe('buildTrustChain: Metrics sink が throw する場合', () => {
  it('元のエラー（FEDERATION_FETCH_FAILED）を置換しない', async () => {
    const fetchFn = async (): Promise<Response> => {
      throw new Error('network');
    };
    const error = await buildTrustChain('https://leaf.example', 'https://anchor.example', {
      fetchFn,
      metrics: throwingMetrics,
    } as never).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(VericertsError);
    expect((error as VericertsError).code).toBe(ErrorCodes.FEDERATION_FETCH_FAILED);
  });
});

describe('postTokenRequest: Metrics sink が throw する場合', () => {
  const params = new URLSearchParams({ grant_type: 'x' });
  const observability = { metrics: throwingMetrics, flow: 'pre-auth' } as const;
  it('成功した TokenResponse を置換しない', async () => {
    const fetchImpl = async (): Promise<Response> =>
      new Response(
        JSON.stringify({
          access_token: 'at',
          token_type: 'Bearer',
          expires_in: 60,
          c_nonce: 'n',
          c_nonce_expires_in: 30,
        }),
        { status: 200, headers: { 'content-type': 'application/json' } },
      );
    const res = await postTokenRequest(
      'https://as.example/token',
      params,
      undefined,
      { fetchImpl },
      observability,
    );
    expect(res.accessToken).toBe('at');
  });
  it('元の TOKEN_REQUEST_FAILED を置換しない', async () => {
    const fetchImpl = async (): Promise<Response> => {
      throw new Error('network');
    };
    const error = await postTokenRequest(
      'https://as.example/token',
      params,
      undefined,
      { fetchImpl },
      observability,
    ).catch((e: unknown) => e);
    expect((error as VericertsError).code).toBe(ErrorCodes.TOKEN_REQUEST_FAILED);
  });
});
