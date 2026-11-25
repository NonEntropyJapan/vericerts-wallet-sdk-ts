/**
 * Wallet ファサードの `buildWuaProofOfPossession` / `refreshWalletAttestation`
 * インスタンスメソッドの回帰テスト。
 *
 * WUA の proof 生成と更新は Wallet のインスタンスメソッドとして提供する。以前は
 * `EudiApi` / `EudiFacade` / `WalletImpl` のいずれにも実装が無く、呼び出すと
 * `TypeError: wallet.buildWuaProofOfPossession is not a function` になっていた
 * （実体は `internal/eudi/wua` の全く異なるシグネチャのフリー関数としてのみ存在した）。
 *
 * - `const pop = await wallet.buildWuaProofOfPossession({ aud, nonce })`
 * - `await wallet.refreshWalletAttestation()`（`refreshedJwt` を
 *   引数に取る形で配線する。旧 WUA・信頼済み Wallet Provider 鍵・現在時刻はファサードが解決し、
 *   呼び出し側は Wallet Provider Backend から取得した新 WUA JWT だけを渡す）
 *
 * どちらも `internal/eudi/wua` の既存フリー関数（`buildWuaProofOfPossession` /
 * `refreshWalletAttestation`）をそのまま呼ぶ薄い委譲であることを確認する。
 */

import { describe, expect, it, setSystemTime } from 'bun:test';
import { decodeCompactJws } from '../../../internal/credential/vc/jws.js';
import { PID_VCT } from '../../../internal/eudi/pid/index.js';
import {
  makeWuaJwt,
  OTHER_PRIVATE_KEY,
  toP256Jwk,
} from '../../../internal/eudi/wua/__tests__/wua-fixtures.js';
import { buildSdJwtVc, createStub, VALID_PID_CLAIMS } from './eudi-fixtures.js';
import {
  codeOf,
  nowSeconds,
  PROVIDER_JWK,
  PROVIDER_KEY,
  setupWalletWithHolderJwk,
  WUA_ENDPOINT,
  wuaRoutes,
} from './wua-fixtures.js';

describe('Wallet EUDI buildWuaProofOfPossession', () => {
  it('現行 WUA 未保持なら 10101 で、生成しない', async () => {
    const stub = createStub(buildSdJwtVc(PID_VCT, VALID_PID_CLAIMS));
    const { wallet } = await setupWalletWithHolderJwk({
      fetchImpl: stub.fetchImpl,
      walletProviderJwk: PROVIDER_JWK,
    });

    expect(
      await codeOf(() =>
        wallet.buildWuaProofOfPossession({ aud: 'https://as.example', nonce: 'n' }),
      ),
    ).toBe('10101');
  });

  it('現行 WUA が期限切れなら 10103 で、生成しない', async () => {
    const now = nowSeconds();
    let jwt = '';
    const stub = createStub(
      buildSdJwtVc(PID_VCT, VALID_PID_CLAIMS),
      wuaRoutes(() => jwt),
    );
    const { wallet, holderJwk } = await setupWalletWithHolderJwk({
      fetchImpl: stub.fetchImpl,
      walletProviderJwk: PROVIDER_JWK,
    });
    jwt = makeWuaJwt(PROVIDER_KEY, { iat: now - 60, exp: now + 60 }, { cnfJwk: holderJwk });
    await wallet.obtainWalletAttestation(WUA_ENDPOINT);

    try {
      setSystemTime(new Date((now + 120) * 1000));
      expect(
        await codeOf(() =>
          wallet.buildWuaProofOfPossession({ aud: 'https://as.example', nonce: 'n' }),
        ),
      ).toBe('10103');
    } finally {
      setSystemTime();
    }
  });

  it('現行 WUA 保持済みなら cnf.jwk にバインドされた鍵で WUA-PoP JWT を生成する', async () => {
    const now = nowSeconds();
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
    const wua = await wallet.obtainWalletAttestation(WUA_ENDPOINT);

    const pop = await wallet.buildWuaProofOfPossession({
      aud: 'https://authorization-server.example',
      nonce: 'c_nonce_value',
    });

    const decoded = decodeCompactJws(pop);
    expect(decoded.header.typ).toBe('wuapop+jwt');
    expect(decoded.payload.aud).toBe('https://authorization-server.example');
    expect(decoded.payload.nonce).toBe('c_nonce_value');
    // iss は WUA `sub`（Wallet Instance ID）から取る（proof.ts の walletInstanceIdOf）。
    expect(decoded.payload.iss).toBe('urn:uuid:550e8400-e29b-41d4-a716-446655440000');
    expect(wua.jwt).toBe(jwt);
  });
});

describe('Wallet EUDI refreshWalletAttestation', () => {
  it('現行 WUA 未保持なら 10101 で、リフレッシュしない', async () => {
    const stub = createStub(buildSdJwtVc(PID_VCT, VALID_PID_CLAIMS));
    const { wallet } = await setupWalletWithHolderJwk({
      fetchImpl: stub.fetchImpl,
      walletProviderJwk: PROVIDER_JWK,
    });

    expect(await codeOf(() => Promise.resolve(wallet.refreshWalletAttestation('x.y.z')))).toBe(
      '10101',
    );
  });

  it('期限切れの現行 WUA を、Wallet Provider が再発行した新 WUA JWT へ差し替える', async () => {
    const now = nowSeconds();
    let jwt = '';
    const stub = createStub(
      buildSdJwtVc(PID_VCT, VALID_PID_CLAIMS),
      wuaRoutes(() => jwt),
    );
    const { wallet, holderJwk } = await setupWalletWithHolderJwk({
      fetchImpl: stub.fetchImpl,
      walletProviderJwk: PROVIDER_JWK,
    });
    jwt = makeWuaJwt(PROVIDER_KEY, { iat: now - 3_600, exp: now + 60 }, { cnfJwk: holderJwk });
    await wallet.obtainWalletAttestation(WUA_ENDPOINT);

    try {
      // 期限（now + 60 秒）を跨いだ時計にして、保持分を期限切れにする。
      setSystemTime(new Date((now + 120) * 1000));
      expect(wallet.getWalletAttestation()).toBeNull();

      const refreshedJwt = makeWuaJwt(
        PROVIDER_KEY,
        { iat: now + 90, exp: now + 3_600 + 90 },
        { cnfJwk: holderJwk },
      );
      const refreshed = wallet.refreshWalletAttestation(refreshedJwt);

      expect(refreshed.jwt).toBe(refreshedJwt);
      expect(wallet.getWalletAttestation()).toBe(refreshed);
    } finally {
      setSystemTime();
    }
  });

  it('WSCD バインドが旧 WUA と一致しない新 WUA JWT は 10102 で、保持を差し替えない', async () => {
    const now = nowSeconds();
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
    const previous = await wallet.obtainWalletAttestation(WUA_ENDPOINT);

    // 旧 WUA とは別の WSCD 鍵にバインドされた新 WUA JWT（鍵すり替え）。
    const mismatchedJwt = makeWuaJwt(
      PROVIDER_KEY,
      { iat: now, exp: now + 3_600 },
      { cnfJwk: toP256Jwk(OTHER_PRIVATE_KEY) },
    );

    expect(
      await codeOf(() => Promise.resolve(wallet.refreshWalletAttestation(mismatchedJwt))),
    ).toBe('10102');
    // 検証に失敗した場合は保持分を差し替えない。
    expect(wallet.getWalletAttestation()).toBe(previous);
  });
});
