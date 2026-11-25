/**
 * Wallet ファサードの `verifySdJwt` が seen-nonces cache の replay 検知経路を通ることの検証。
 *
 * `nonceStore` + `nonceContext` を渡したときだけ使用 1 回が保証される。
 * SDK は永続ストアを内蔵しない方針のため、
 * ストア未注入では従来どおりバインド一致のみを検証する。
 */

import { describe, expect, it } from 'bun:test';
import type { NonceContext } from '../../../internal/auth/nonce/index.js';
import { createNonceStore } from '../../../internal/auth/nonce/index.js';
import {
  CNF,
  SESSION_SIGNER,
} from '../../../internal/credential/sdjwt/__tests__/key-binding.fixtures.js';
import { addKeyBinding } from '../../../internal/credential/sdjwt/verify.js';
import { ErrorCodes, VericertsError } from '../../../internal/errors.js';
import { ethereumPath } from '../../../internal/keymanager/hd.js';
import { MemoryStorage } from '../../../storage/storage.js';
import { createWallet } from '../../factory.js';

const TEST_MNEMONIC =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const NONCE = 'AQIDBAUGBwgJCgsMDQ4PEA';
const CLIENT = 'https://verifier.example/client';
const CTX: NonceContext = { flow: 'oid4vp', clientId: CLIENT };

/** cnf 付き SD-JWT を発行し、KB-JWT を付けた提示を返す。 */
async function setup() {
  const wallet = await createWallet({ storage: new MemoryStorage() });
  await wallet.importMnemonic(TEST_MNEMONIC);
  const keyPair = await wallet.deriveKey(ethereumPath(0, 0));
  const document = await wallet.createDID('key', { keyID: keyPair.id });
  const nowSeconds = Math.floor(Date.now() / 1000);

  const sdJwt = await wallet.issueSdJwt(keyPair.id, {
    vct: 'urn:test:identity',
    issuer: document.id,
    cnf: CNF,
    disclosureClaims: ['name'],
    claims: { name: 'Alice' },
  });
  const presented = addKeyBinding(sdJwt, SESSION_SIGNER, {
    nonce: NONCE,
    audience: CLIENT,
    iatSeconds: nowSeconds,
  });
  return { wallet, presented, nowSeconds };
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

describe('Wallet.verifySdJwt の replay 検知配線', () => {
  it('nonceStore を渡すと 1 回目は成功し 2 回目は 4010 REPLAY_DETECTED', async () => {
    const { wallet, presented, nowSeconds } = await setup();
    const store = createNonceStore({ backend: 'memory' });
    const opts = {
      nonce: NONCE,
      nonceStore: store,
      nonceContext: CTX,
      nowSeconds,
    };

    const verified = await wallet.verifySdJwt(presented, opts);
    expect(verified.claims.name).toBe('Alice');
    expect(await store.has(NONCE, CTX)).toBe(true);

    expect(await errorCode(() => wallet.verifySdJwt(presented, opts))).toBe(
      ErrorCodes.REPLAY_DETECTED,
    );
  });

  it('nonceStore 未指定なら従来どおり何度でも検証できる（オプトイン）', async () => {
    const { wallet, presented, nowSeconds } = await setup();
    const opts = { nonce: NONCE, nowSeconds };
    await expect(wallet.verifySdJwt(presented, opts)).resolves.toBeDefined();
    await expect(wallet.verifySdJwt(presented, opts)).resolves.toBeDefined();
  });

  it('nonceStore ありで nonce 未指定なら 4013 NONCE_MALFORMED', async () => {
    const { wallet, presented, nowSeconds } = await setup();
    const store = createNonceStore({ backend: 'memory' });
    expect(
      await errorCode(() =>
        wallet.verifySdJwt(presented, { nonceStore: store, nonceContext: CTX, nowSeconds }),
      ),
    ).toBe(ErrorCodes.NONCE_MALFORMED);
  });

  it('client_id が KB-JWT の aud と不一致なら 4012', async () => {
    const { wallet, presented, nowSeconds } = await setup();
    const store = createNonceStore({ backend: 'memory' });
    expect(
      await errorCode(() =>
        wallet.verifySdJwt(presented, {
          nonce: NONCE,
          nonceStore: store,
          nonceContext: { flow: 'oid4vp', clientId: 'https://evil.example/client' },
          nowSeconds,
        }),
      ),
    ).toBe(ErrorCodes.NONCE_BINDING_MISMATCH);
  });
});

// 片方だけの指定を通常検証へ落とすと、配線漏れのまま同じ KB-JWT を何度でも受理する（fail-open）。
describe('Wallet.verifySdJwt の片方だけ指定は fail-closed', () => {
  it('nonceStore だけを渡した場合は 4012 で拒否し、2 回目以降も受理されない', async () => {
    const { wallet, presented, nowSeconds } = await setup();
    const store = createNonceStore({ backend: 'memory' });
    const opts = { nonce: NONCE, nonceStore: store, nowSeconds };

    for (let i = 0; i < 2; i += 1) {
      expect(await errorCode(() => wallet.verifySdJwt(presented, opts))).toBe(
        ErrorCodes.NONCE_BINDING_MISMATCH,
      );
    }
    expect(await store.has(NONCE, CTX)).toBe(false);
  });

  it('nonceContext だけを渡した場合は 4010 で拒否し、2 回目以降も受理されない', async () => {
    const { wallet, presented, nowSeconds } = await setup();
    const opts = { nonce: NONCE, nonceContext: CTX, nowSeconds };

    for (let i = 0; i < 2; i += 1) {
      expect(await errorCode(() => wallet.verifySdJwt(presented, opts))).toBe(
        ErrorCodes.REPLAY_DETECTED,
      );
    }
  });

  it('値が undefined の明示キー（配線漏れ）も片方だけとして拒否する', async () => {
    const { wallet, presented, nowSeconds } = await setup();
    const store = createNonceStore({ backend: 'memory' });
    expect(
      await errorCode(() =>
        wallet.verifySdJwt(presented, {
          nonce: NONCE,
          nonceStore: store,
          nonceContext: undefined,
          nowSeconds,
        }),
      ),
    ).toBe(ErrorCodes.NONCE_BINDING_MISMATCH);
  });

  it('両方とも指定しない（replay 検知を使わない明示）は従来どおり何度でも通る', async () => {
    const { wallet, presented, nowSeconds } = await setup();
    const opts = { nonce: NONCE, nonceStore: undefined, nonceContext: undefined, nowSeconds };
    await expect(wallet.verifySdJwt(presented, opts)).resolves.toBeDefined();
    await expect(wallet.verifySdJwt(presented, opts)).resolves.toBeDefined();
  });
});
