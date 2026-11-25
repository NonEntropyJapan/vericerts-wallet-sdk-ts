/**
 * Wallet ファサードの再検証パスへの `requireHolderBinding` 中継の回帰テスト。
 *
 * ファサードは `verifyPresentation` プリミティブの結果を捨てて `attachCredentialResults` で
 * `credentialResults` を組み直す（発行者鍵を DID 解決で自動補完するため）。したがって
 * **プリミティブ側だけ突合を実装しても、ファサード経由の検証では効かない**。中継漏れは
 * 「`wallet.verifyPresentation(jwt, { requireHolderBinding: true })` が第三者の VC を
 * `valid: true` で返す」という形で表面化する。
 *
 * did:key の自己発行・自己検証（実署名・ネット非依存）で配線を確認する。
 */

import { describe, expect, it } from 'bun:test';
import {
  VC_V2_CONTEXT,
  type VerifiableCredential,
  type VerifiablePresentation,
} from '../../../internal/credential/index.js';
import { ethereumPath } from '../../../internal/keymanager/hd.js';
import { MemoryStorage } from '../../../storage/storage.js';
import { createWallet } from '../../factory.js';
import {
  assertPresentationInvalid,
  embeddedErrorCodes,
  issueCodes,
} from '../verification-result.fixtures.js';

const TEST_MNEMONIC =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
/** 第三者の subject（この Wallet の DID ではない）。VC 自体は正当に発行される。 */
const OTHER_SUBJECT_DID = 'did:example:subject';

/** did:key を自己発行済みの Wallet・鍵 ID・DID を用意する。 */
async function setupIssuer() {
  const wallet = await createWallet({ storage: new MemoryStorage() });
  await wallet.importMnemonic(TEST_MNEMONIC);
  const keyPair = await wallet.deriveKey(ethereumPath(0, 0));
  const document = await wallet.createDID('key', { keyID: keyPair.id });
  return { wallet, keyID: keyPair.id, did: document.id };
}

/** `credentialSubject` を差し替えた VC を組み立てる。 */
function vcFor(issuer: string, credentialSubject: Record<string, unknown>): VerifiableCredential {
  return {
    '@context': [VC_V2_CONTEXT],
    type: ['VerifiableCredential'],
    issuer,
    credentialSubject,
    issuanceDate: '2025-01-01T00:00:00Z',
    expirationDate: '2030-01-01T00:00:00Z',
    id: 'urn:uuid:vc-1',
  } as unknown as VerifiableCredential;
}

/** 内包 VC を持つ JWT-VP を発行する。 */
async function issueVpWith(
  wallet: Awaited<ReturnType<typeof setupIssuer>>['wallet'],
  keyID: string,
  did: string,
  entries: readonly string[],
): Promise<string> {
  const vp: VerifiablePresentation = {
    '@context': [VC_V2_CONTEXT],
    type: ['VerifiablePresentation'],
    holder: did,
    verifiableCredential: entries,
  };
  return wallet.issuePresentation(vp, keyID);
}

describe('Wallet.verifyPresentation の requireHolderBinding 中継', () => {
  it('第三者の VC を詰めた VP は requireHolderBinding: true で 3012 として弾かれる', async () => {
    const { wallet, keyID, did } = await setupIssuer();
    const foreign = await wallet.issueCredential(vcFor(did, { id: OTHER_SUBJECT_DID }), keyID);
    const jwt = await issueVpWith(wallet, keyID, did, [foreign]);

    const verified = assertPresentationInvalid(
      await wallet.verifyPresentation(jwt, {
        allowUnbound: true,
        requireHolderBinding: true,
      }),
    );
    expect(verified.holderDID).toBe(did);
    expect(verified.presentationValid).toBe(true);
    expect(embeddedErrorCodes(verified.credentialResults[0])).toEqual(['3012']);
    expect(issueCodes(verified.errors)).toEqual(['3012']);
  });

  it('削除済みの delegationsを JS 呼び出しで渡しても無視され 3012 のまま', async () => {
    const { wallet, keyID, did } = await setupIssuer();
    const foreign = await wallet.issueCredential(vcFor(did, { id: OTHER_SUBJECT_DID }), keyID);
    const jwt = await issueVpWith(wallet, keyID, did, [foreign]);
    const options = {
      allowUnbound: true,
      requireHolderBinding: true,
      delegations: [{ subjectDID: OTHER_SUBJECT_DID, holderDID: did, scope: ['read', 'present'] }],
    } as unknown as Parameters<typeof wallet.verifyPresentation>[1];

    const verified = assertPresentationInvalid(await wallet.verifyPresentation(jwt, options));
    expect(embeddedErrorCodes(verified.credentialResults[0])).toEqual(['3012']);
  });

  it('既定（未指定）では従来どおり第三者の VC でも valid: true（後方互換）', async () => {
    const { wallet, keyID, did } = await setupIssuer();
    const foreign = await wallet.issueCredential(vcFor(did, { id: OTHER_SUBJECT_DID }), keyID);
    const jwt = await issueVpWith(wallet, keyID, did, [foreign]);

    const verified = await wallet.verifyPresentation(jwt, { allowUnbound: true });
    expect(verified.valid).toBe(true);
  });

  it('sub === vp.holder の VC は requireHolderBinding: true でも valid: true', async () => {
    const { wallet, keyID, did } = await setupIssuer();
    const own = await wallet.issueCredential(vcFor(did, { id: did, name: 'Alice' }), keyID);
    const jwt = await issueVpWith(wallet, keyID, did, [own]);

    const verified = await wallet.verifyPresentation(jwt, {
      allowUnbound: true,
      requireHolderBinding: true,
    });
    expect(verified.valid).toBe(true);
  });

  it('sub を持たない bearer VC は requireHolderBinding: true で拒否される', async () => {
    const { wallet, keyID, did } = await setupIssuer();
    const bearer = await wallet.issueCredential(vcFor(did, { name: 'Alice' }), keyID);
    const jwt = await issueVpWith(wallet, keyID, did, [bearer]);

    const strict = assertPresentationInvalid(
      await wallet.verifyPresentation(jwt, {
        allowUnbound: true,
        requireHolderBinding: true,
      }),
    );
    expect(embeddedErrorCodes(strict.credentialResults[0])).toEqual(['3012']);

    const lenient = await wallet.verifyPresentation(jwt, { allowUnbound: true });
    expect(lenient.valid).toBe(true);
  });

  it('内包 SD-JWT VC は cnf / KB-JWT を持たなければ requireHolderBinding: true で拒否される', async () => {
    const { wallet, keyID, did } = await setupIssuer();
    const sdJwt = await wallet.issueSdJwt(keyID, {
      vct: 'https://example.com/credentials/identity',
      disclosureClaims: ['name'],
      claims: { name: 'Alice' },
      salts: { name: 'salt-name' },
      issuer: did,
    });
    const jwt = await issueVpWith(wallet, keyID, did, [sdJwt]);

    const verified = assertPresentationInvalid(
      await wallet.verifyPresentation(jwt, {
        allowUnbound: true,
        requireHolderBinding: true,
      }),
    );
    expect(embeddedErrorCodes(verified.credentialResults[0])).toEqual(['3012']);
  });
});
