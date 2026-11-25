/**
 * `StatusFacade.createStatusListResolver` の `onPolicyEvent` と `GdprFacade.revokeConsent` の
 * `Object.prototype` 汚染耐性テスト。
 *
 * - `onPolicyEvent` を**省略した**正当な呼び出しが汚染関数を採用すると、Fail-open の監査レコードが
 *   攻撃者の関数へ流れ、Dashboard ログへ一切残らない。
 * - 空スコープの `revokeConsent({})` は汚染された `vcId` 等で `GDPR_CONSENT_NOT_FOUND` のガードを素通りする。
 */

import { describe, expect, it } from 'bun:test';
import { withPollutedPrototypeAsync } from '../../../internal/__tests__/prototype-pollution.fixtures.js';
import type { PublicKeyJwk } from '../../../internal/identity/did.js';
import { MemoryStorage } from '../../../storage/storage.js';
import { createWallet } from '../../factory.js';

const TEST_MNEMONIC =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

const DUMMY_ISSUER_KEY: PublicKeyJwk = {
  kty: 'EC',
  crv: 'P-256',
  x: 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
  y: 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
};

async function setup() {
  const storage = new MemoryStorage();
  const wallet = await createWallet({ storage });
  await wallet.importMnemonic(TEST_MNEMONIC);
  const persona = await wallet.createPersona();
  await wallet.setActivePersona(persona.id);
  return { wallet, storage };
}

describe('Object.prototype 汚染下の StatusFacade / GdprFacade', () => {
  it('onPolicyEvent 省略時は汚染関数ではなく既定の Dashboard ログ記録先が使われる', async () => {
    const { wallet, storage } = await setup();
    const leaked: unknown[] = [];

    await withPollutedPrototypeAsync(
      { onPolicyEvent: (event: unknown) => leaked.push(event) },
      async () => {
        const resolver = await wallet.createStatusListResolver({
          fetchToken: async () => {
            throw new Error('network unreachable');
          },
          issuerPublicKey: DUMMY_ISSUER_KEY,
          purpose: 'revocation',
          failSafePolicy: { suppressPrompt: ['FO-1'] },
        });
        await resolver.resolve({ status_list: { idx: 0, uri: 'https://issuer.example/status/1' } });
      },
    );

    expect(leaked).toEqual([]);
    expect((await storage.list('dashboard-log/')).length).toBe(1);
  });

  it('汚染された vcId があっても revokeConsent({}) は GDPR_CONSENT_NOT_FOUND(10603) を投げる', async () => {
    const { wallet } = await setup();

    await withPollutedPrototypeAsync(
      { vcId: 'polluted-vc', rpIdentifier: 'https://x.example' },
      async () => {
        await expect(wallet.revokeConsent({})).rejects.toMatchObject({ code: '10603' });
      },
    );
  });
});
