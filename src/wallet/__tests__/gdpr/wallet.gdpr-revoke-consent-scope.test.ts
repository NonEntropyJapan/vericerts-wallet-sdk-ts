/**
 * Wallet ファサードの recordPresentation / revokeConsent スコープ解決の統合テスト。
 *
 * `wallet.gdpr.test.ts` から分離（linterly の 1 ファイル行数上限対応）。
 *
 * - recordPresentation → revokeConsent({ rpIdentifier }) は presentedTo が一致する VC を処理制限にし、
 *   当該 RP の Pseudonym を破棄済みとしてマークする（修正前は rpIdentifier 単独スコープが no-op だった）。
 * - 未存在 VC の recordPresentation は VC_NOT_FOUND(3070)。
 */

import { describe, expect, it } from 'bun:test';
import type { VerifiableCredential } from '../../../internal/credential/index.js';
import { ErrorCodes, VericertsError } from '../../../internal/errors.js';
import { MemoryStorage } from '../../../storage/storage.js';
import { createWallet } from '../../factory.js';
import type { Wallet } from '../../types.js';

const TEST_MNEMONIC =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const VC_V2_CONTEXT = 'https://www.w3.org/ns/credentials/v2';

/** import + アクティブペルソナ設定済みの Wallet と共有 storage を用意する。 */
async function setup(): Promise<{ wallet: Wallet; storage: MemoryStorage }> {
  const storage = new MemoryStorage();
  const wallet = await createWallet({ storage });
  await wallet.importMnemonic(TEST_MNEMONIC);
  const persona = await wallet.createPersona();
  await wallet.setActivePersona(persona.id);
  return { wallet, storage };
}

/** テスト用の最小 VC。 */
function makeVc(id: string): VerifiableCredential {
  return {
    '@context': [VC_V2_CONTEXT],
    type: ['VerifiableCredential'],
    issuer: 'did:example:issuer',
    credentialSubject: { id: 'did:example:subject', name: 'Alice' },
    issuanceDate: '2026-01-01T00:00:00Z',
    id,
  };
}

describe('Wallet GDPR recordPresentation / revokeConsent スコープ解決', () => {
  it('recordPresentation → revokeConsent({ rpIdentifier }) は presentedTo が一致する VC を処理制限にし、当該 RP の Pseudonym を破棄済みとしてマークする', async () => {
    const { wallet, storage } = await setup();
    await wallet.storeCredential(makeVc('vc-1'));
    await wallet.storeCredential(makeVc('vc-2'));
    await wallet.recordPresentation('vc-1', 'did:web:rp.example', 'kyc');
    await wallet.recordPresentation('vc-2', 'did:web:other.example');

    await wallet.revokeConsent({ rpIdentifier: 'did:web:rp.example' });

    // 修正前は rpIdentifier 単独スコープが no-op だった: 該当 RP へ提示済みの vc-1 のみ処理制限される。
    expect((await wallet.getCredentialRecord('vc-1'))?.processingRestricted).toBe(true);
    // 別 RP へ提示した vc-2 は対象外。
    expect((await wallet.getCredentialRecord('vc-2'))?.processingRestricted).toBeUndefined();
    // PersonaManager.discardPseudonym への配線: 破棄フラグが storage に永続化される。
    expect(await storage.get('pseudonym-discarded/did:web:rp.example')).not.toBeNull();
  });

  it('未存在 VC の recordPresentation は VC_NOT_FOUND(3070)', async () => {
    const { wallet } = await setup();
    await expect(wallet.recordPresentation('missing', 'did:web:rp.example')).rejects.toThrow(
      new VericertsError(ErrorCodes.VC_NOT_FOUND),
    );
  });
});
