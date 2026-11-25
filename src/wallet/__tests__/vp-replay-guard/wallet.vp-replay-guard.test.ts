/**
 * Wallet ファサードの `verifyPresentation` が seen-nonces cache の replay 検知経路を通ることの検証。
 *
 * `nonceStore` + `nonceContext` を渡したときだけ使用 1 回が保証される。
 * SDK は永続ストアを内蔵しない方針のため、
 * ストア未注入では従来どおりバインド一致のみを検証する。
 */

import { describe, expect, it } from 'bun:test';
import type { NonceContext } from '../../../internal/auth/nonce/index.js';
import { createNonceStore } from '../../../internal/auth/nonce/index.js';
import { VC_V2_CONTEXT, type VerifiablePresentation } from '../../../internal/credential/index.js';
import { ErrorCodes, VericertsError } from '../../../internal/errors.js';
import { ethereumPath } from '../../../internal/keymanager/hd.js';
import { MemoryStorage } from '../../../storage/storage.js';
import { createWallet } from '../../factory.js';
import { assertPresentationInvalid } from '../verification-result.fixtures.js';

const TEST_MNEMONIC =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const NONCE = 'AQIDBAUGBwgJCgsMDQ4PEA';
const OTHER_NONCE = 'BQIDBAUGBwgJCgsMDQ4PEA';
const CLIENT = 'https://verifier.example/client';
const CTX: NonceContext = { flow: 'oid4vp', clientId: CLIENT };

/** did:key 自己発行の JWT-VP（aud / nonce バインド付き）を用意する。 */
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

/** 与えた async 関数の VericertsError code を返す（成功時は null）。 */
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

describe('Wallet.verifyPresentationEnvelopeStrict の replay 検知配線', () => {
  it('nonceStore を渡すと 1 回目は成功し 2 回目は 4010 REPLAY_DETECTED', async () => {
    const { wallet, presented, nowSeconds, did } = await setup();
    const store = createNonceStore({ backend: 'memory' });
    const opts = {
      expectedNonce: NONCE,
      nonceStore: store,
      nonceContext: CTX,
      nowSeconds,
    };

    const verified = await wallet.verifyPresentationEnvelopeStrict(presented, opts);
    expect(verified.payload.iss).toBe(did);
    expect(await store.has(NONCE, CTX)).toBe(true);

    expect(await errorCode(() => wallet.verifyPresentationEnvelopeStrict(presented, opts))).toBe(
      ErrorCodes.REPLAY_DETECTED,
    );
  });

  it('nonceStore 未指定なら従来どおり何度でも検証できる（オプトイン）', async () => {
    const { wallet, presented, nowSeconds } = await setup();
    const opts = { expectedAudience: CLIENT, expectedNonce: NONCE, nowSeconds };
    await expect(wallet.verifyPresentationEnvelopeStrict(presented, opts)).resolves.toBeDefined();
    await expect(wallet.verifyPresentationEnvelopeStrict(presented, opts)).resolves.toBeDefined();
  });

  it('nonceStore ありで expectedNonce 未指定なら 4013 NONCE_MALFORMED', async () => {
    const { wallet, presented, nowSeconds } = await setup();
    const store = createNonceStore({ backend: 'memory' });
    expect(
      await errorCode(() =>
        wallet.verifyPresentationEnvelopeStrict(presented, {
          nonceStore: store,
          nonceContext: CTX,
          nowSeconds,
        }),
      ),
    ).toBe(ErrorCodes.NONCE_MALFORMED);
  });

  it('expectedNonce が VP の nonce と不一致なら 3012 で、nonce は消費されない', async () => {
    const { wallet, presented, nowSeconds } = await setup();
    const store = createNonceStore({ backend: 'memory' });
    expect(
      await errorCode(() =>
        wallet.verifyPresentationEnvelopeStrict(presented, {
          expectedNonce: OTHER_NONCE,
          nonceStore: store,
          nonceContext: CTX,
          nowSeconds,
        }),
      ),
    ).toBe(ErrorCodes.HOLDER_BIND_MISMATCH);
    expect(await store.has(OTHER_NONCE, CTX)).toBe(false);
    expect(await store.has(NONCE, CTX)).toBe(false);
  });

  it('client_id が VP の aud と不一致なら 4012', async () => {
    const { wallet, presented, nowSeconds } = await setup();
    const store = createNonceStore({ backend: 'memory' });
    expect(
      await errorCode(() =>
        wallet.verifyPresentationEnvelopeStrict(presented, {
          expectedNonce: NONCE,
          nonceStore: store,
          nonceContext: { flow: 'oid4vp', clientId: 'https://evil.example/client' },
          nowSeconds,
        }),
      ),
    ).toBe(ErrorCodes.NONCE_BINDING_MISMATCH);
  });
});

// replay 検知は nonceStore と nonceContext の両方が揃って初めて成立する。片方だけの指定を
// 通常検証へ落とすと、配線漏れのまま同じ JWT-VP を何度でも受理する（fail-open）。
describe('Wallet.verifyPresentation* の片方だけ指定は fail-closed', () => {
  it('nonceStore だけを渡した場合は 4012 で拒否し、2 回目以降も受理されない', async () => {
    const { wallet, presented, nowSeconds } = await setup();
    const store = createNonceStore({ backend: 'memory' });
    const opts = { expectedNonce: NONCE, nonceStore: store, nowSeconds };

    for (let i = 0; i < 2; i += 1) {
      expect(await errorCode(() => wallet.verifyPresentationEnvelopeStrict(presented, opts))).toBe(
        ErrorCodes.NONCE_BINDING_MISMATCH,
      );
    }
    expect(await store.has(NONCE, CTX)).toBe(false);
  });

  it('nonceContext だけを渡した場合は 4010 で拒否し、2 回目以降も受理されない', async () => {
    const { wallet, presented, nowSeconds } = await setup();
    const opts = { expectedNonce: NONCE, nonceContext: CTX, nowSeconds };

    for (let i = 0; i < 2; i += 1) {
      expect(await errorCode(() => wallet.verifyPresentationEnvelopeStrict(presented, opts))).toBe(
        ErrorCodes.REPLAY_DETECTED,
      );
    }
  });

  it('値が undefined の明示キー（配線漏れ）も片方だけとして拒否する', async () => {
    const { wallet, presented, nowSeconds } = await setup();
    const store = createNonceStore({ backend: 'memory' });
    expect(
      await errorCode(() =>
        wallet.verifyPresentationEnvelopeStrict(presented, {
          expectedNonce: NONCE,
          nonceStore: store,
          nonceContext: undefined,
          nowSeconds,
        }),
      ),
    ).toBe(ErrorCodes.NONCE_BINDING_MISMATCH);
  });

  it('高レベル verifyPresentation も片方だけなら presentationValid:false（4012 / 4010）', async () => {
    const { wallet, presented, nowSeconds } = await setup();
    const store = createNonceStore({ backend: 'memory' });
    const onlyStore = assertPresentationInvalid(
      await wallet.verifyPresentation(presented, {
        expectedNonce: NONCE,
        nonceStore: store,
        nowSeconds,
      }),
    );
    const onlyContext = assertPresentationInvalid(
      await wallet.verifyPresentation(presented, {
        expectedNonce: NONCE,
        nonceContext: CTX,
        nowSeconds,
      }),
    );
    expect(onlyStore.presentationValid).toBe(false);
    expect(onlyContext.presentationValid).toBe(false);
    expect(onlyStore.errors[0]?.code).toBe(ErrorCodes.NONCE_BINDING_MISMATCH);
    expect(onlyContext.errors[0]?.code).toBe(ErrorCodes.REPLAY_DETECTED);
  });

  it('両方とも指定しない（replay 検知を使わない明示）は従来どおり通り、両方指定は 1 回だけ通る', async () => {
    const { wallet, presented, nowSeconds } = await setup();
    const base = { expectedAudience: CLIENT, expectedNonce: NONCE, nowSeconds };
    await expect(
      wallet.verifyPresentationEnvelopeStrict(presented, {
        ...base,
        nonceStore: undefined,
        nonceContext: undefined,
      }),
    ).resolves.toBeDefined();

    const store = createNonceStore({ backend: 'memory' });
    const both = { expectedNonce: NONCE, nonceStore: store, nonceContext: CTX, nowSeconds };
    await expect(wallet.verifyPresentationEnvelopeStrict(presented, both)).resolves.toBeDefined();
    expect(await errorCode(() => wallet.verifyPresentationEnvelopeStrict(presented, both))).toBe(
      ErrorCodes.REPLAY_DETECTED,
    );
  });
});
