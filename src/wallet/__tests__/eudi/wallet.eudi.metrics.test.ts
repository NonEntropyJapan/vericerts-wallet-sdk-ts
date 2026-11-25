/**
 * `EudiFacade` のメトリクス配線テスト。
 *
 * `receivePID` / `presentPID` / `obtainWalletAttestation` の 3 API が実フロー
 * （`createWallet({ metrics })` 経由、`eudiFetchImpl` 注入・グローバル `fetch` 非依存）から
 * `vericerts_pid_issuance_total` / `vericerts_oid4vp_response_duration_seconds` /
 * `vericerts_wua_refresh_total` を記録することを固定する。
 */

import { describe, expect, it } from 'bun:test';
import { VericertsError } from '../../../internal/errors.js';
import { PID_VCT } from '../../../internal/eudi/pid/index.js';
import { makeWuaJwt } from '../../../internal/eudi/wua/__tests__/wua-fixtures.js';
import { createInMemoryMetrics, MetricNames } from '../../../internal/observability/metrics.js';
import { MemoryStorage } from '../../../storage/storage.js';
import { createWallet } from '../../factory.js';
import {
  buildSdJwtVc,
  createStub,
  offerURI,
  requestURI,
  TEST_MNEMONIC,
  VALID_PID_CLAIMS,
} from './eudi-fixtures.js';
import {
  CHALLENGE_URL,
  ISSUE_URL,
  nowSeconds,
  PROVIDER_JWK,
  PROVIDER_KEY,
  setupWalletWithHolderJwk,
  WUA_ENDPOINT,
  wuaRoutes,
} from './wua-fixtures.js';

describe('EudiFacade.receivePID / presentPID のメトリクス配線', () => {
  it('receivePID 成功で pid_issuance_total{result=success} を記録する', async () => {
    const stub = createStub(buildSdJwtVc(PID_VCT, VALID_PID_CLAIMS));
    const { metrics, snapshot } = createInMemoryMetrics();
    const wallet = await createWallet({
      storage: new MemoryStorage(),
      eudiFetchImpl: stub.fetchImpl,
      metrics,
    });
    await wallet.importMnemonic(TEST_MNEMONIC);
    const persona = await wallet.createPersona();
    await wallet.setActivePersona(persona.id);

    await wallet.receivePID(offerURI());

    expect(
      snapshot().counters.find((c) => c.name === MetricNames.PID_ISSUANCE_TOTAL)?.labels.result,
    ).toBe('success');
    // 受領フロー内の pre-authorized_code Token Request も同じ metrics へ配線されている。
    expect(
      snapshot().histograms.find((h) => h.name === MetricNames.OID4VCI_TOKEN_DURATION_SECONDS)
        ?.labels,
    ).toEqual({ flow: 'pre-auth' });
  });

  it('receivePID 失敗（アクティブペルソナ未設定）で pid_issuance_total{result=failure} を記録する', async () => {
    const { metrics, snapshot } = createInMemoryMetrics();
    const wallet = await createWallet({ storage: new MemoryStorage(), metrics });

    await expect(wallet.receivePID(offerURI())).rejects.toBeInstanceOf(VericertsError);

    expect(
      snapshot().counters.find((c) => c.name === MetricNames.PID_ISSUANCE_TOTAL)?.labels.result,
    ).toBe('failure');
  });

  it('presentPID で oid4vp_response_duration_seconds{format=sd-jwt} を記録する', async () => {
    const stub = createStub(buildSdJwtVc(PID_VCT, VALID_PID_CLAIMS));
    const { metrics, snapshot } = createInMemoryMetrics();
    const wallet = await createWallet({
      storage: new MemoryStorage(),
      eudiFetchImpl: stub.fetchImpl,
      metrics,
    });
    await wallet.importMnemonic(TEST_MNEMONIC);
    const persona = await wallet.createPersona();
    await wallet.setActivePersona(persona.id);
    await wallet.receivePID(offerURI());

    await wallet.presentPID(requestURI(), ['family_name', 'given_name']);

    const histogram = snapshot().histograms.find(
      (h) => h.name === MetricNames.OID4VP_RESPONSE_DURATION_SECONDS,
    );
    expect(histogram?.labels).toEqual({ format: 'sd-jwt' });
    expect(histogram?.count).toBe(1);
  });
});

describe('EudiFacade.obtainWalletAttestation のメトリクス配線', () => {
  it('取得成功で wua_refresh_total{result=success} を記録する', async () => {
    const { metrics, snapshot } = createInMemoryMetrics();
    const now = nowSeconds();
    const jwt = makeWuaJwt(PROVIDER_KEY, { iat: now - 60, exp: now + 3_600 });
    const stub = createStub(
      buildSdJwtVc(PID_VCT, VALID_PID_CLAIMS),
      wuaRoutes(() => jwt),
    );
    const { wallet } = await setupWalletWithHolderJwk({
      fetchImpl: stub.fetchImpl,
      walletProviderJwk: PROVIDER_JWK,
      metrics,
    });

    await wallet.obtainWalletAttestation(WUA_ENDPOINT);

    expect(
      snapshot().counters.find((c) => c.name === MetricNames.WUA_REFRESH_TOTAL)?.labels.result,
    ).toBe('success');
    expect(stub.calls.map((call) => call.url)).toEqual([CHALLENGE_URL, ISSUE_URL]);
  });

  it('walletProviderJwk 未設定の失敗で wua_refresh_total{result=failure} を記録する', async () => {
    const { metrics, snapshot } = createInMemoryMetrics();
    const stub = createStub(buildSdJwtVc(PID_VCT, VALID_PID_CLAIMS));
    const { wallet } = await setupWalletWithHolderJwk({ fetchImpl: stub.fetchImpl, metrics });

    await expect(wallet.obtainWalletAttestation(WUA_ENDPOINT)).rejects.toBeInstanceOf(
      VericertsError,
    );

    expect(
      snapshot().counters.find((c) => c.name === MetricNames.WUA_REFRESH_TOTAL)?.labels.result,
    ).toBe('failure');
  });
});
