/**
 * Wallet ファサードの `obtainWalletAttestation` 失敗経路。
 *
 * どの失敗でも**現行 WUA を保持しない**（`getWalletAttestation()` は `null` のまま）ことを、
 * `createWallet` 経由（実 storage / 実鍵 / アクティブペルソナ）で固定する。
 *
 * - `walletProviderJwk` 未設定は `10102` で、通信を 1 回も起こさない（fail-closed）
 * - 信頼していない鍵で署名された WUA は `10102`、期限切れは `10103`
 * - 非 HTTPS のエンドポイントは `10101` で、通信を 1 回も起こさない
 * - 2 段フローのどちらの段の非 2xx も `10101`（challenge 段で落ちたら `/wua/issue` へ進まない）
 *
 * 正常系は `wallet.eudi.wua.test.ts`。ネットワークは `eudiFetchImpl` の注入のみで再現する。
 */

import { describe, expect, it } from 'bun:test';
import { PID_VCT } from '../../../internal/eudi/pid/index.js';
import { makeWuaJwt } from '../../../internal/eudi/wua/__tests__/wua-fixtures.js';
import { buildSdJwtVc, createStub, VALID_PID_CLAIMS } from './eudi-fixtures.js';
import {
  CHALLENGE_BODY,
  CHALLENGE_URL,
  codeOf,
  ISSUE_URL,
  jsonResponse,
  nowSeconds,
  OTHER_PROVIDER_KEY,
  PROVIDER_JWK,
  PROVIDER_KEY,
  setupWalletWithHolderJwk,
  WUA_ENDPOINT,
  wuaRoutes,
} from './wua-fixtures.js';

describe('Wallet EUDI obtainWalletAttestation の失敗（保持しない）', () => {
  it('walletProviderJwk 未設定は WUA_VERIFICATION_FAILED(10102) で通信も起こさない', async () => {
    const now = nowSeconds();
    const jwt = makeWuaJwt(PROVIDER_KEY, { iat: now - 60, exp: now + 3_600 });
    const stub = createStub(
      buildSdJwtVc(PID_VCT, VALID_PID_CLAIMS),
      wuaRoutes(() => jwt),
    );
    const { wallet } = await setupWalletWithHolderJwk({ fetchImpl: stub.fetchImpl });

    expect(await codeOf(() => wallet.obtainWalletAttestation(WUA_ENDPOINT))).toBe('10102');
    // 信頼済み鍵が無いまま取得しに行かない（未検証の WUA を掴む余地を作らない）。
    expect(stub.calls).toHaveLength(0);
    expect(wallet.getWalletAttestation()).toBeNull();
  });

  it('信頼していない鍵で署名された WUA は 10102 で、保持もしない', async () => {
    const now = nowSeconds();
    const jwt = makeWuaJwt(OTHER_PROVIDER_KEY, { iat: now - 60, exp: now + 3_600 });
    const stub = createStub(
      buildSdJwtVc(PID_VCT, VALID_PID_CLAIMS),
      wuaRoutes(() => jwt),
    );
    const { wallet } = await setupWalletWithHolderJwk({
      fetchImpl: stub.fetchImpl,
      walletProviderJwk: PROVIDER_JWK,
    });

    expect(await codeOf(() => wallet.obtainWalletAttestation(WUA_ENDPOINT))).toBe('10102');
    expect(wallet.getWalletAttestation()).toBeNull();
  });

  it('期限切れの WUA は 10103 で、保持もしない', async () => {
    const now = nowSeconds();
    const jwt = makeWuaJwt(PROVIDER_KEY, { iat: now - 7_200, exp: now - 60 });
    const stub = createStub(
      buildSdJwtVc(PID_VCT, VALID_PID_CLAIMS),
      wuaRoutes(() => jwt),
    );
    const { wallet } = await setupWalletWithHolderJwk({
      fetchImpl: stub.fetchImpl,
      walletProviderJwk: PROVIDER_JWK,
    });

    expect(await codeOf(() => wallet.obtainWalletAttestation(WUA_ENDPOINT))).toBe('10103');
    expect(wallet.getWalletAttestation()).toBeNull();
  });

  it('非 HTTPS のエンドポイントは WUA_FETCH_FAILED(10101) で通信も起こさない', async () => {
    const stub = createStub(buildSdJwtVc(PID_VCT, VALID_PID_CLAIMS));
    const { wallet } = await setupWalletWithHolderJwk({
      fetchImpl: stub.fetchImpl,
      walletProviderJwk: PROVIDER_JWK,
    });

    expect(
      await codeOf(() => wallet.obtainWalletAttestation('http://wallet-provider.example.eu/wua')),
    ).toBe('10101');
    expect(stub.calls).toHaveLength(0);
    expect(wallet.getWalletAttestation()).toBeNull();
  });

  it('/wua/challenge の非 2xx 応答は 10101 で、/wua/issue へ進まない', async () => {
    const stub = createStub(buildSdJwtVc(PID_VCT, VALID_PID_CLAIMS), {
      [CHALLENGE_URL]: () => new Response('', { status: 500 }),
    });
    const { wallet } = await setupWalletWithHolderJwk({
      fetchImpl: stub.fetchImpl,
      walletProviderJwk: PROVIDER_JWK,
    });

    expect(await codeOf(() => wallet.obtainWalletAttestation(WUA_ENDPOINT))).toBe('10101');
    expect(stub.calls.map((call) => call.url)).toEqual([CHALLENGE_URL]);
    expect(wallet.getWalletAttestation()).toBeNull();
  });

  it('/wua/issue の非 2xx 応答は 10101', async () => {
    const stub = createStub(buildSdJwtVc(PID_VCT, VALID_PID_CLAIMS), {
      [CHALLENGE_URL]: () => jsonResponse(CHALLENGE_BODY),
      [ISSUE_URL]: () => new Response('', { status: 500 }),
    });
    const { wallet } = await setupWalletWithHolderJwk({
      fetchImpl: stub.fetchImpl,
      walletProviderJwk: PROVIDER_JWK,
    });

    expect(await codeOf(() => wallet.obtainWalletAttestation(WUA_ENDPOINT))).toBe('10101');
    expect(wallet.getWalletAttestation()).toBeNull();
  });
});
