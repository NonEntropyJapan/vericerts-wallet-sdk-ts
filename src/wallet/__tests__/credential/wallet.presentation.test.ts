/**
 * Wallet ファサードの credential 操作の統合テスト。
 *
 * createWallet が presentation / sdjwt プリミティブへ薄く委譲していることを、did:key の自己発行・
 * 自己検証（実署名・ネット非依存）で検証する:
 * - issuePresentation → verifyPresentationEnvelopeStrict（aud / nonce 照合含む）
 * - issueSdJwt → verifySdJwt（vct / 開示クレーム復元）
 * - 未登録鍵での発行は KEY_NOT_FOUND(1004)
 * - verifyCredentialStrict / verifyPresentationEnvelopeStrict の `clockSkewSeconds` がプリミティブへ素通しされる
 */

import { describe, expect, it } from 'bun:test';
import {
  VC_V2_CONTEXT,
  type VerifiableCredential,
  type VerifiablePresentation,
} from '../../../internal/credential/index.js';
import { VericertsError } from '../../../internal/errors.js';
import { ethereumPath } from '../../../internal/keymanager/hd.js';
import { MemoryStorage } from '../../../storage/storage.js';
import { createWallet } from '../../factory.js';

const TEST_MNEMONIC =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

/** import + 既定パス derive + did:key 自己発行済みの Wallet・鍵 ID・DID を用意する。 */
async function setupIssuer() {
  const wallet = await createWallet({ storage: new MemoryStorage() });
  await wallet.importMnemonic(TEST_MNEMONIC);
  const keyPair = await wallet.deriveKey(ethereumPath(0, 0));
  const document = await wallet.createDID('key', { keyID: keyPair.id });
  return { wallet, keyID: keyPair.id, did: document.id };
}

/** 与えた async 関数を実行し、VericertsError の code を返す（成功時は null）。 */
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

describe('Wallet.issuePresentation / verifyPresentationEnvelopeStrict', () => {
  it('did:key 自己発行 → 自己検証で往復できる（鍵非露出・ネット非依存）', async () => {
    const { wallet, keyID, did } = await setupIssuer();
    const vp: VerifiablePresentation = {
      '@context': [VC_V2_CONTEXT],
      type: ['VerifiablePresentation'],
      holder: did,
      verifiableCredential: [],
    };

    const jwt = await wallet.issuePresentation(vp, keyID);
    expect(jwt.split('.').length).toBe(3);

    // バインドを持たない VP は allowUnbound で明示オプトアウトして検証する。
    const verified = await wallet.verifyPresentationEnvelopeStrict(jwt, { allowUnbound: true });
    expect(verified.payload.iss).toBe(did);
    expect(verified.presentation.holder).toBe(did);
  });

  it('既定では aud/nonce 未指定の検証はバインド未検証として 3012（リプレイ防止）', async () => {
    const { wallet, keyID, did } = await setupIssuer();
    const vp: VerifiablePresentation = {
      '@context': [VC_V2_CONTEXT],
      type: ['VerifiablePresentation'],
      holder: did,
      verifiableCredential: [],
    };
    const jwt = await wallet.issuePresentation(vp, keyID, {
      audience: 'https://verifier.example',
      nonce: 'n-123',
    });
    // 期待値を渡さずに検証 → 既定束縛モードで拒否（修正前は成功してしまう回帰）。
    expect(await errorCode(() => wallet.verifyPresentationEnvelopeStrict(jwt))).toBe('3012');
  });

  it('audience / nonce を付与して発行し、期待値一致で検証できる', async () => {
    const { wallet, keyID, did } = await setupIssuer();
    const vp: VerifiablePresentation = {
      '@context': [VC_V2_CONTEXT],
      type: ['VerifiablePresentation'],
      holder: did,
      verifiableCredential: [],
    };
    const jwt = await wallet.issuePresentation(vp, keyID, {
      audience: 'https://verifier.example',
      nonce: 'n-123',
    });
    const verified = await wallet.verifyPresentationEnvelopeStrict(jwt, {
      expectedAudience: 'https://verifier.example',
      expectedNonce: 'n-123',
    });
    expect(verified.payload.aud).toBe('https://verifier.example');
  });

  it('nonce 不一致は HOLDER_BIND_MISMATCH(3012)', async () => {
    const { wallet, keyID, did } = await setupIssuer();
    const vp: VerifiablePresentation = {
      '@context': [VC_V2_CONTEXT],
      type: ['VerifiablePresentation'],
      holder: did,
      verifiableCredential: [],
    };
    const jwt = await wallet.issuePresentation(vp, keyID, {
      audience: 'https://verifier.example',
      nonce: 'n-123',
    });
    // aud は一致、nonce のみ不一致（束縛モードで nonce 不一致を突く）。
    expect(
      await errorCode(() =>
        wallet.verifyPresentationEnvelopeStrict(jwt, {
          expectedAudience: 'https://verifier.example',
          expectedNonce: 'other',
        }),
      ),
    ).toBe('3012');
  });

  it('expiresInSeconds 付き発行は exp を過ぎると VC_EXPIRED(3024)', async () => {
    const { wallet, keyID, did } = await setupIssuer();
    const vp: VerifiablePresentation = {
      '@context': [VC_V2_CONTEXT],
      type: ['VerifiablePresentation'],
      holder: did,
      verifiableCredential: [],
    };
    const jwt = await wallet.issuePresentation(vp, keyID, {
      audience: 'https://verifier.example',
      nonce: 'n-1',
      expiresInSeconds: 3600,
      nowSeconds: 1000,
    });
    // now=5000s は exp(4600s) を過ぎている。
    expect(
      await errorCode(() =>
        wallet.verifyPresentationEnvelopeStrict(jwt, {
          expectedAudience: 'https://verifier.example',
          expectedNonce: 'n-1',
          nowSeconds: 5000,
        }),
      ),
    ).toBe('3024');
  });

  it('未登録鍵 ID での発行は KEY_NOT_FOUND(1004)', async () => {
    const { wallet, did } = await setupIssuer();
    const vp: VerifiablePresentation = {
      '@context': [VC_V2_CONTEXT],
      type: ['VerifiablePresentation'],
      holder: did,
      verifiableCredential: [],
    };
    expect(await errorCode(() => wallet.issuePresentation(vp, 'missing-key'))).toBe('1004');
  });
});

describe('Wallet.issueSdJwt / verifySdJwt', () => {
  it('SD-JWT を発行 → iss(自DID)解決で検証し、開示クレームを復元する', async () => {
    const { wallet, keyID, did } = await setupIssuer();
    const sdJwt = await wallet.issueSdJwt(keyID, {
      vct: 'urn:test:identity',
      issuer: did,
      disclosureClaims: ['name'],
      claims: { name: 'Alice', role: 'admin' },
    });
    // SD-JWT は `<issuerJwt>~<disclosure>~` 形式（末尾 ~）。
    expect(sdJwt.includes('~')).toBe(true);

    const verified = await wallet.verifySdJwt(sdJwt, { expectedVct: 'urn:test:identity' });
    expect(verified.vct).toBe('urn:test:identity');
    // 開示クレーム（name）と平文クレーム（role）の双方が復元される。
    expect(verified.claims.name).toBe('Alice');
    expect(verified.claims.role).toBe('admin');
  });

  it('未登録鍵 ID での発行は KEY_NOT_FOUND(1004)', async () => {
    const { wallet, did } = await setupIssuer();
    expect(
      await errorCode(() =>
        wallet.issueSdJwt('missing-key', {
          vct: 'urn:test:identity',
          issuer: did,
          disclosureClaims: [],
          claims: { name: 'Alice' },
        }),
      ),
    ).toBe('1004');
  });
});

describe('Wallet の clockSkewSeconds 配線', () => {
  /** exp = 4600s の束縛付き VP を発行する。 */
  async function issueBoundVp() {
    const { wallet, keyID, did } = await setupIssuer();
    const vp: VerifiablePresentation = {
      '@context': [VC_V2_CONTEXT],
      type: ['VerifiablePresentation'],
      holder: did,
      verifiableCredential: [],
    };
    const jwt = await wallet.issuePresentation(vp, keyID, {
      audience: 'https://verifier.example',
      nonce: 'n-1',
      expiresInSeconds: 3600,
      nowSeconds: 1000,
    });
    return { wallet, jwt };
  }

  const EXPECTED = {
    expectedAudience: 'https://verifier.example',
    expectedNonce: 'n-1',
  } as const;

  it('既定スキュー（VP は 30s）では exp + 10s でも検証成功する', async () => {
    const { wallet, jwt } = await issueBoundVp();
    const verified = await wallet.verifyPresentationEnvelopeStrict(jwt, {
      ...EXPECTED,
      nowSeconds: 4610,
    });
    expect(verified.payload.exp).toBe(4600);
  });

  it('clockSkewSeconds: 0 を渡すと同じ VP が VC_EXPIRED(3024) になる（素通しの確認）', async () => {
    const { wallet, jwt } = await issueBoundVp();
    expect(
      await errorCode(() =>
        wallet.verifyPresentationEnvelopeStrict(jwt, {
          ...EXPECTED,
          nowSeconds: 4610,
          clockSkewSeconds: 0,
        }),
      ),
    ).toBe('3024');
  });

  it('VP のキャップ超過（31）は CLOCK_SKEW_OPTION_INVALID(4015)', async () => {
    const { wallet, jwt } = await issueBoundVp();
    expect(
      await errorCode(() =>
        wallet.verifyPresentationEnvelopeStrict(jwt, {
          ...EXPECTED,
          nowSeconds: 2000,
          clockSkewSeconds: 31,
        }),
      ),
    ).toBe('4015');
  });

  it('verifyCredentialStrict のキャップ超過（121）は CLOCK_SKEW_OPTION_INVALID(4015)', async () => {
    const { wallet, keyID, did } = await setupIssuer();
    const vc: VerifiableCredential = {
      '@context': [VC_V2_CONTEXT],
      type: ['VerifiableCredential'],
      issuer: did,
      credentialSubject: { id: did, name: 'Alice' },
      issuanceDate: '2025-12-01T00:00:00Z',
      expirationDate: '2027-01-01T00:00:00Z',
    };
    const jwt = await wallet.issueCredential(vc, keyID, { nowSeconds: 1_767_225_600 });
    // nowSeconds を必ず注入する。省略すると Date.now() に落ち、(a) オプション検証が時刻評価より
    // 後ろへ動いた場合に 3024 へ化け、(b) fixture の expirationDate（2027-01-01）を過ぎた時点で
    // 無関係な理由で落ちる（wall-clock 依存の時限爆弾になる）。
    expect(
      await errorCode(() =>
        wallet.verifyCredentialStrict(jwt, { nowSeconds: 1_767_225_600, clockSkewSeconds: 121 }),
      ),
    ).toBe('4015');
    const verified = await wallet.verifyCredentialStrict(jwt, { nowSeconds: 1_767_225_600 });
    expect(verified.payload.iss).toBe(did);
  });
});
