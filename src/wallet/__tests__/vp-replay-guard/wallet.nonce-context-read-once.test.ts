/**
 * Wallet ファサードの replay 検知（メトリクス計装を含む）が元の `nonceContext` を
 * **検証全体で `flow` 1 回**しか読まないことの回帰テスト。
 *
 * `flow` を own のアクセサにすると読み取りごとに値が変わり得る。計装が catch 節で元オブジェクトの
 * `flow` を読み直すと、(1) 仕様が封じた層ごとの再読（TOCTOU）が残り、(2) 読み取りが例外を投げると
 * 4010 `REPLAY_DETECTED` が握りつぶされる。
 */

import { describe, expect, it } from 'bun:test';
import type { NonceContext } from '../../../internal/auth/nonce/index.js';
import { createNonceStore } from '../../../internal/auth/nonce/index.js';
import { VC_V2_CONTEXT, type VerifiablePresentation } from '../../../internal/credential/index.js';
import {
  CNF,
  SESSION_SIGNER,
} from '../../../internal/credential/sdjwt/__tests__/key-binding.fixtures.js';
import { addKeyBinding } from '../../../internal/credential/sdjwt/verify.js';
import { ErrorCodes } from '../../../internal/errors.js';
import { ethereumPath } from '../../../internal/keymanager/hd.js';
import { createInMemoryMetrics, MetricNames } from '../../../internal/observability/metrics.js';
import { MemoryStorage } from '../../../storage/storage.js';
import { createWallet } from '../../factory.js';

const TEST_MNEMONIC =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const NONCE = 'AQIDBAUGBwgJCgsMDQ4PEA';
const CLIENT = 'https://verifier.example/client';

/** `flow` を 3 回目の読み取りで throw する own アクセサにした NonceContext と、読み取り回数の参照。 */
function throwingFlowContext(): { context: NonceContext; reads: () => number } {
  let reads = 0;
  const context = { clientId: CLIENT } as Record<string, unknown>;
  Object.defineProperty(context, 'flow', {
    enumerable: true,
    get() {
      reads += 1;
      if (reads >= 3) {
        throw new Error('getter boom');
      }
      return 'oid4vp';
    },
  });
  return { context: context as unknown as NonceContext, reads: () => reads };
}

async function setupWallet() {
  const { metrics, snapshot } = createInMemoryMetrics();
  const wallet = await createWallet({ storage: new MemoryStorage(), metrics });
  await wallet.importMnemonic(TEST_MNEMONIC);
  const keyPair = await wallet.deriveKey(ethereumPath(0, 0));
  const document = await wallet.createDID('key', { keyID: keyPair.id });
  const nowSeconds = Math.floor(Date.now() / 1000);
  return { wallet, snapshot, keyPair, did: document.id, nowSeconds };
}

describe('replay 検知のメトリクス計装は元の nonceContext の flow を読み直さない', () => {
  it('verifyPresentationEnvelopeStrict: flow 読み取りは 1 回で、2 回目も 4010 が保たれ replay が集計される', async () => {
    const { wallet, snapshot, keyPair, did, nowSeconds } = await setupWallet();
    const vp: VerifiablePresentation = {
      '@context': [VC_V2_CONTEXT],
      type: ['VerifiablePresentation'],
      holder: did,
      verifiableCredential: [],
    };
    const presented = await wallet.issuePresentation(vp, keyPair.id, {
      audience: CLIENT,
      nonce: NONCE,
      nowSeconds,
    });
    const { context, reads } = throwingFlowContext();
    const opts = {
      expectedNonce: NONCE,
      nonceStore: createNonceStore({ backend: 'memory' }),
      nonceContext: context,
      nowSeconds,
    };

    await wallet.verifyPresentationEnvelopeStrict(presented, opts);
    expect(reads()).toBe(1);

    await expect(wallet.verifyPresentationEnvelopeStrict(presented, opts)).rejects.toMatchObject({
      code: ErrorCodes.REPLAY_DETECTED,
    });
    expect(reads()).toBe(2);
    expect(
      snapshot().counters.find(
        (sample) =>
          sample.name === MetricNames.NONCE_REPLAY_DETECTED_TOTAL &&
          sample.labels.context === 'oid4vp',
      )?.value,
    ).toBe(1);
  });

  it('verifySdJwt: flow 読み取りは 1 回で、2 回目も 4010 が保たれる', async () => {
    const { wallet, keyPair, did, nowSeconds } = await setupWallet();
    const sdJwt = await wallet.issueSdJwt(keyPair.id, {
      vct: 'urn:test:identity',
      issuer: did,
      cnf: CNF,
      disclosureClaims: ['name'],
      claims: { name: 'Alice' },
    });
    const presented = addKeyBinding(sdJwt, SESSION_SIGNER, {
      nonce: NONCE,
      audience: CLIENT,
      iatSeconds: nowSeconds,
    });
    const { context, reads } = throwingFlowContext();
    const opts = {
      nonce: NONCE,
      nonceStore: createNonceStore({ backend: 'memory' }),
      nonceContext: context,
      nowSeconds,
    };

    await wallet.verifySdJwt(presented, opts);
    expect(reads()).toBe(1);

    await expect(wallet.verifySdJwt(presented, opts)).rejects.toMatchObject({
      code: ErrorCodes.REPLAY_DETECTED,
    });
    expect(reads()).toBe(2);
  });
});
