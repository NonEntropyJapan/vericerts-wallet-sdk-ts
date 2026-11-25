/**
 * Wallet ファサードの WUA API統合テスト用フィクスチャ。
 *
 * 取得の 2 段フローを `eudiFetchImpl` の注入だけで再現するための
 * 経路表と、Wallet の初期化ヘルパを集める。正常系（`wallet.eudi.wua.test.ts`）と失敗経路
 * （`wallet.eudi.wua.failures.test.ts`）の両方から使う。鍵素材は実鍵のみ。
 */

import { expect } from 'bun:test';
import { VericertsError } from '../../../internal/errors.js';
import { toP256Jwk } from '../../../internal/eudi/wua/__tests__/wua-fixtures.js';
import type { PublicKeyJwk } from '../../../internal/identity/did.js';
import { createP256CredentialSigner } from '../../../internal/keymanager/credential-signer.js';
import { deriveSlip10Nist256p1 } from '../../../internal/keymanager/derivation/slip10.js';
import { mnemonicToSeed } from '../../../internal/keymanager/hd.js';
import type { Metrics } from '../../../internal/observability/metrics.js';
import { MemoryStorage } from '../../../storage/storage.js';
import { createWallet } from '../../factory.js';
import type { Wallet } from '../../types.js';
import { type createStub, TEST_MNEMONIC } from './eudi-fixtures.js';

/** Wallet Provider（WUA 署名者）の秘密鍵と、`walletProviderJwk` に渡す信頼済み公開鍵。 */
export const PROVIDER_KEY = new Uint8Array(32).fill(3);
export const PROVIDER_JWK = toP256Jwk(PROVIDER_KEY);

/** 信頼していない Wallet Provider の鍵（署名者すり替えの再現用）。 */
export const OTHER_PROVIDER_KEY = new Uint8Array(32).fill(9);

/** Wallet Provider Backend のベース URL（HTTPS）と、2 段フローの各要求 URL。 */
export const WUA_ENDPOINT = 'https://wallet-provider.example.eu/wallet-unit-attestation';
export const CHALLENGE_URL = `${WUA_ENDPOINT}/wua/challenge`;
export const ISSUE_URL = `${WUA_ENDPOINT}/wua/issue`;

/** `/wua/challenge` が返す既定の challenge / nonce。 */
export const CHALLENGE_BODY: Readonly<Record<string, unknown>> = {
  challenge: 'Y2hhbGxlbmdl',
  nonce: 'bm9uY2U',
};

/** 現在時刻（NumericDate、秒）。ファサードは実時計を使うため実時刻を基準にする。 */
export function nowSeconds(): number {
  return Math.floor(Date.now() / 1000);
}

/** JSON 本文の 200 応答を返す。 */
export function jsonResponse(body: Readonly<Record<string, unknown>>): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  });
}

/**
 * 2 段フローを最後まで通す WUA 経路を組み立てる。
 *
 * `/wua/issue` の応答は遅延評価する（`cnf.jwk` に載せる鍵が Wallet を作るまで判らないケースで、
 * 経路表を先に組み立てておけるようにするため）。
 *
 * @param jwt `/wua/issue` が返す WUA JWT を返す関数。
 */
export function wuaRoutes(jwt: () => string): Readonly<Record<string, () => Response>> {
  return {
    [CHALLENGE_URL]: () => jsonResponse(CHALLENGE_BODY),
    [ISSUE_URL]: () => jsonResponse({ wallet_attestation: jwt() }),
  };
}

/** 投げられた VericertsError のコードを取り出す（投げなければ失敗させる）。 */
export async function codeOf(run: () => Promise<unknown>): Promise<string> {
  try {
    await run();
  } catch (e) {
    expect(e).toBeInstanceOf(VericertsError);
    return (e as VericertsError).code;
  }
  throw new Error('should throw');
}

/**
 * ニーモニック import とアクティブペルソナ設定まで済ませた Wallet と、その署名鍵の公開 JWK を作る。
 *
 * `holderJwk` はアクティブペルソナと同じ導出パスから実際に導出する（モック鍵は使わない）。WUA-PoP と
 * `/wua/challenge` の Proof はこの鍵で署名されるため、`cnf.jwk` に載せる鍵と一致させたいテストが使う。
 */
export async function setupWalletWithHolderJwk(
  options: Readonly<{
    fetchImpl: ReturnType<typeof createStub>['fetchImpl'];
    walletProviderJwk?: PublicKeyJwk;
    wscdPublicKeyJwk?: PublicKeyJwk;
    metrics?: Metrics;
  }>,
): Promise<{ wallet: Wallet; holderJwk: PublicKeyJwk }> {
  const wallet = await createWallet({
    storage: new MemoryStorage(),
    eudiFetchImpl: options.fetchImpl,
    ...(options.walletProviderJwk === undefined
      ? {}
      : { walletProviderJwk: options.walletProviderJwk }),
    ...(options.wscdPublicKeyJwk === undefined
      ? {}
      : { wscdPublicKeyJwk: options.wscdPublicKeyJwk }),
    ...(options.metrics === undefined ? {} : { metrics: options.metrics }),
  });
  await wallet.importMnemonic(TEST_MNEMONIC);
  const persona = await wallet.createPersona();
  await wallet.setActivePersona(persona.id);
  // 公開 API は privateKey を返さないため、同じニーモニック・パスから SLIP-0010（P-256）で導出する。
  const { privateKey } = deriveSlip10Nist256p1(
    mnemonicToSeed(TEST_MNEMONIC),
    persona.derivationPath,
  );
  const holderJwk = createP256CredentialSigner(privateKey).publicKeyJwk as PublicKeyJwk;
  return { wallet, holderJwk };
}
