/**
 * Wallet ファサードの検証オプションの `Object.prototype` 汚染耐性テスト。
 *
 * `const { nonceStore, nonceContext } = opts ?? {}` はプロトタイプ鎖を辿るため、これらを
 * **渡していない**正当な検証でも汚染値が揃って replay 検知経路へ入り、seen-nonce の記録先が
 * 攻撃者提供のストアへ委譲される（記録先が攻撃者側になるため、再提示が「初回」と判定される）。
 *
 * 汚染下でも「ストア未注入 ＝ 従来どおりバインド一致のみを検証する」経路のままであることを、
 * 攻撃者ストアが一切呼ばれないことと、`expectedNonce` 必須化（4013）が発火しないことで検証する。
 */

import { describe, expect, it } from 'bun:test';
import { withPollutedPrototypeAsync } from '../../../internal/__tests__/prototype-pollution.fixtures.js';
import type { NonceContext, NonceStore } from '../../../internal/auth/nonce/index.js';
import { VC_V2_CONTEXT, type VerifiablePresentation } from '../../../internal/credential/index.js';
import { ErrorCodes, VericertsError } from '../../../internal/errors.js';
import { ethereumPath } from '../../../internal/keymanager/hd.js';
import { MemoryStorage } from '../../../storage/storage.js';
import { createWallet } from '../../factory.js';

const TEST_MNEMONIC =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const NONCE = 'AQIDBAUGBwgJCgsMDQ4PEA';
const CLIENT = 'https://verifier.example/client';
const CTX: NonceContext = { flow: 'oid4vp', clientId: CLIENT };

/** 呼ばれた回数を数える攻撃者提供の nonce ストア。 */
function spyStore(): { store: NonceStore; calls: string[] } {
  const calls: string[] = [];
  const store: NonceStore = {
    has: async () => {
      calls.push('has');
      return false;
    },
    consume: async () => {
      calls.push('consume');
      return true;
    },
    purgeExpired: async () => {
      calls.push('purgeExpired');
      return 0;
    },
  } as unknown as NonceStore;
  return { store, calls };
}

async function setup() {
  const wallet = await createWallet({ storage: new MemoryStorage() });
  await wallet.importMnemonic(TEST_MNEMONIC);
  const keyPair = await wallet.deriveKey(ethereumPath(0, 0));
  const document = await wallet.createDID('key', { keyID: keyPair.id });
  const nowSeconds = Math.floor(Date.now() / 1000);

  const vp: VerifiablePresentation = {
    '@context': [VC_V2_CONTEXT],
    type: ['VerifiablePresentation'],
    holder: document.id,
    verifiableCredential: [],
  };
  const presented = await wallet.issuePresentation(vp, keyPair.id, {
    audience: CLIENT,
    nonce: NONCE,
    nowSeconds,
  });
  return { wallet, presented, nowSeconds, did: document.id };
}

async function errorCode(fn: () => Promise<unknown>): Promise<string | null> {
  try {
    await fn();
    return null;
  } catch (error) {
    if (error instanceof VericertsError) {
      return error.code;
    }
    throw error;
  }
}

describe('Wallet 検証オプションの Object.prototype 汚染耐性', () => {
  it('継承した nonceStore / nonceContext は replay 検知経路を起動しない（VP）', async () => {
    const { wallet, presented, nowSeconds, did } = await setup();
    const { store, calls } = spyStore();

    const verified = await withPollutedPrototypeAsync(
      { nonceStore: store, nonceContext: CTX },
      () =>
        // `nonceStore` / `nonceContext` を渡していない検証。汚染値を拾えば replay 経路へ入り、
        // `expectedNonce` 必須化により 4013 で失敗する（かつ攻撃者ストアが呼ばれる）。
        wallet.verifyPresentationEnvelopeStrict(presented, {
          expectedAudience: CLIENT,
          expectedNonce: NONCE,
          nowSeconds,
        }),
    );

    expect(verified.payload.iss).toBe(did);
    expect(calls).toEqual([]);
  });

  it('継承した nonceStore / nonceContext は expectedNonce の必須化を引き起こさない', async () => {
    const { wallet, presented, nowSeconds } = await setup();
    const { store, calls } = spyStore();

    const code = await withPollutedPrototypeAsync({ nonceStore: store, nonceContext: CTX }, () =>
      errorCode(() => wallet.verifyPresentationEnvelopeStrict(presented, { nowSeconds })),
    );

    // ストア未注入の経路なので 4013 は発火しない。
    expect(code).not.toBe(ErrorCodes.NONCE_MALFORMED);
    expect(calls).toEqual([]);
  });

  it('明示的に渡した nonceStore は従来どおり replay を検知する（正常系）', async () => {
    const { wallet, presented, nowSeconds, did } = await setup();
    const { createNonceStore } = await import('../../../internal/auth/nonce/index.js');
    const store = createNonceStore({ backend: 'memory' });
    const opts = { expectedNonce: NONCE, nonceStore: store, nonceContext: CTX, nowSeconds };

    const verified = await wallet.verifyPresentationEnvelopeStrict(presented, opts);
    expect(verified.payload.iss).toBe(did);
    expect(await errorCode(() => wallet.verifyPresentationEnvelopeStrict(presented, opts))).toBe(
      ErrorCodes.REPLAY_DETECTED,
    );
  });
});
