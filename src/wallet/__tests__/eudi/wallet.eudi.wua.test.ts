/**
 * Wallet ファサードの Wallet Unit Attestation API統合テスト
 *
 * `createWallet` 経由（実 storage / 実鍵 / アクティブペルソナ）で次を検証する。
 * - `obtainWalletAttestation` が 2 段フロー（`/wua/challenge` →
 *   `/wua/issue`）で WUA を取得して保持し、`getWalletAttestation` がそれを返す（取得前は `null`）。
 * - 保持済み WUA が期限切れになった後の `getWalletAttestation` は `null`。
 * - `wscdPublicKeyJwk` を設定した Wallet は WUA `cnf.jwk` のバインドも検証する。
 * - 取得後は `receivePID(offerURI, { walletAttestation: true })` が成功する（
 *   `10101` に倒れていた経路が閉じたことの回帰）。
 *
 * 失敗経路（保持しないこと）は `wallet.eudi.wua.failures.test.ts`。ネットワークは
 * `eudiFetchImpl` の注入のみで再現し、グローバル `fetch` は差し替えない。
 */

import { describe, expect, it, setSystemTime } from 'bun:test';
import { PID_VCT } from '../../../internal/eudi/pid/index.js';
import {
  makeWuaJwt,
  OTHER_PRIVATE_KEY,
  toP256Jwk,
  WSCD_PRIVATE_KEY,
} from '../../../internal/eudi/wua/__tests__/wua-fixtures.js';
import type { PublicKeyJwk } from '../../../internal/identity/did.js';
import type { Wallet } from '../../types.js';
import {
  buildSdJwtVc,
  createStub,
  offerURI,
  TOKEN_URL,
  VALID_PID_CLAIMS,
} from './eudi-fixtures.js';
import {
  CHALLENGE_URL,
  codeOf,
  ISSUE_URL,
  nowSeconds,
  PROVIDER_JWK,
  PROVIDER_KEY,
  setupWalletWithHolderJwk,
  WUA_ENDPOINT,
  wuaRoutes,
} from './wua-fixtures.js';

describe('Wallet EUDI obtainWalletAttestation / getWalletAttestation', () => {
  it('取得前の getWalletAttestation は null', async () => {
    const stub = createStub(buildSdJwtVc(PID_VCT, VALID_PID_CLAIMS));
    const { wallet } = await setupWalletWithHolderJwk({
      fetchImpl: stub.fetchImpl,
      walletProviderJwk: PROVIDER_JWK,
    });

    expect(wallet.getWalletAttestation()).toBeNull();
    expect(stub.calls).toHaveLength(0);
  });

  it('obtainWalletAttestation は 2 段フローで WUA を取得して保持する', async () => {
    const now = nowSeconds();
    const jwt = makeWuaJwt(PROVIDER_KEY, { iat: now - 60, exp: now + 3_600 });
    const stub = createStub(
      buildSdJwtVc(PID_VCT, VALID_PID_CLAIMS),
      wuaRoutes(() => jwt),
    );
    const { wallet, holderJwk } = await setupWalletWithHolderJwk({
      fetchImpl: stub.fetchImpl,
      walletProviderJwk: PROVIDER_JWK,
    });

    const wua = await wallet.obtainWalletAttestation(WUA_ENDPOINT);

    expect(wua.jwt).toBe(jwt);
    expect(wua.walletProviderDID).toBe('https://wallet-provider.example.eu');
    expect(stub.calls.map((call) => call.url)).toEqual([CHALLENGE_URL, ISSUE_URL]);
    // challenge 要求にはアクティブペルソナの公開鍵を devicePubKey として載せる。
    expect(JSON.parse(stub.calls[0]?.body ?? '{}')).toEqual({ devicePubKey: holderJwk });
    expect(wallet.getWalletAttestation()).toBe(wua);
  });

  it('保持済み WUA が期限切れになった後の getWalletAttestation は null', async () => {
    const now = nowSeconds();
    const jwt = makeWuaJwt(PROVIDER_KEY, { iat: now - 60, exp: now + 60 });
    const stub = createStub(
      buildSdJwtVc(PID_VCT, VALID_PID_CLAIMS),
      wuaRoutes(() => jwt),
    );
    const { wallet } = await setupWalletWithHolderJwk({
      fetchImpl: stub.fetchImpl,
      walletProviderJwk: PROVIDER_JWK,
    });
    await wallet.obtainWalletAttestation(WUA_ENDPOINT);
    expect(wallet.getWalletAttestation()).not.toBeNull();

    try {
      // 期限（now + 60 秒）を跨いだ時計で読む。同期アクセサなので時刻以外は変えない。
      setSystemTime(new Date((now + 120) * 1000));
      expect(wallet.getWalletAttestation()).toBeNull();
    } finally {
      setSystemTime();
    }
  });
});

describe('Wallet EUDI obtainWalletAttestation の WSCD バインド', () => {
  /** `makeWuaJwt` 既定の `cnf.jwk`（= WSCD 由来鍵）で 2 段フローを通す Wallet を作る。 */
  async function setupBindingCase(wscdPublicKeyJwk: PublicKeyJwk): Promise<Wallet> {
    const now = nowSeconds();
    const jwt = makeWuaJwt(PROVIDER_KEY, { iat: now - 60, exp: now + 3_600 });
    const stub = createStub(
      buildSdJwtVc(PID_VCT, VALID_PID_CLAIMS),
      wuaRoutes(() => jwt),
    );
    const { wallet } = await setupWalletWithHolderJwk({
      fetchImpl: stub.fetchImpl,
      walletProviderJwk: PROVIDER_JWK,
      wscdPublicKeyJwk,
    });
    return wallet;
  }

  it('wscdPublicKeyJwk と cnf.jwk が一致すれば取得して保持する', async () => {
    const wallet = await setupBindingCase(toP256Jwk(WSCD_PRIVATE_KEY));

    const wua = await wallet.obtainWalletAttestation(WUA_ENDPOINT);

    expect(wua.cnf.jwk).toEqual(toP256Jwk(WSCD_PRIVATE_KEY));
    expect(wallet.getWalletAttestation()).toBe(wua);
  });

  it('wscdPublicKeyJwk と cnf.jwk が一致しなければ 10102 で、保持もしない', async () => {
    const wallet = await setupBindingCase(toP256Jwk(OTHER_PRIVATE_KEY));

    expect(await codeOf(() => wallet.obtainWalletAttestation(WUA_ENDPOINT))).toBe('10102');
    expect(wallet.getWalletAttestation()).toBeNull();
  });
});

describe('Wallet EUDI WUA 取得と受領のつながり', () => {
  it('obtainWalletAttestation の後は walletAttestation: true の receivePID が成功する', async () => {
    const now = nowSeconds();
    // WUA `cnf.jwk` はアクティブペルソナの鍵にバインドする（WUA-PoP の署名鍵と一致させる）。
    // その鍵は Wallet を作るまで判らないので、応答は生成後に差し込む。
    let jwt = '';
    const stub = createStub(
      buildSdJwtVc(PID_VCT, VALID_PID_CLAIMS),
      wuaRoutes(() => jwt),
    );
    const { wallet, holderJwk } = await setupWalletWithHolderJwk({
      fetchImpl: stub.fetchImpl,
      walletProviderJwk: PROVIDER_JWK,
    });
    jwt = makeWuaJwt(PROVIDER_KEY, { iat: now - 60, exp: now + 3_600 }, { cnfJwk: holderJwk });

    // 取得前は WUA 未保持なので 10101（従来の唯一の挙動）。
    expect(await codeOf(() => wallet.receivePID(offerURI(), { walletAttestation: true }))).toBe(
      '10101',
    );

    await wallet.obtainWalletAttestation(WUA_ENDPOINT);
    const pid = await wallet.receivePID(offerURI(), { walletAttestation: true });

    expect(pid.vct).toBe(PID_VCT);
    // Token Request に OAuth2 Attestation-Based Client Authentication が載る。
    const tokenCall = stub.calls.find((call) => call.url === TOKEN_URL);
    const params = new URLSearchParams(tokenCall?.body ?? '');
    expect(params.get('client_assertion')?.startsWith(`${jwt}~`)).toBe(true);
    expect(params.get('client_assertion_type')).toBe(
      'urn:ietf:params:oauth:client-assertion-type:jwt-client-attestation',
    );
  });
});
