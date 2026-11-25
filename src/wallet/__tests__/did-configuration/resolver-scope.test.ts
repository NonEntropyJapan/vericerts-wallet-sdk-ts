/**
 * `verifyDIDConfiguration` の発行者 DID 解決は 1 回の検証で共有される。
 *
 * DLC の発行者 DID 解決は署名検証より前に走る。素の resolver を DLC ごとに呼ぶと、外部オリジンが
 * `linked_dids`（最大 32 件）に署名不正の DLC を並べるだけで、検証側に DID Log の取得・検証を件数ぶん
 * 強いられる（did:webvh 1 件の解決が 0.8 秒なら 26 秒）。同一 DID の解決が 1 回に集約されることを、
 * 下位メソッドの `resolve` 呼び出し回数で pin する。
 */

import { describe, expect, it, spyOn } from 'bun:test';
import { MethodKey } from '../../../internal/identity/method-key.js';
import { MemoryStorage } from '../../../storage/storage.js';
import { MAX_LINKED_DIDS } from '../../did/facade.js';
import { createWallet } from '../../factory.js';

const ORIGIN = 'https://example.com';
const TEST_MNEMONIC =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

/** JWT の署名部だけを改変した文字列を返す（署名検証失敗の再現）。 */
function tamperSignature(jwt: string): string {
  const [header, payload, signature] = jwt.split('.');
  const flipped = `${signature?.startsWith('A') === true ? 'B' : 'A'}${signature?.slice(1) ?? ''}`;
  return `${header}.${payload}.${flipped}`;
}

describe('Wallet.verifyDIDConfiguration: 発行者 DID 解決の集約', () => {
  it.each([
    ['有効な DLC', (jwt: string) => jwt, true],
    ['署名不正の DLC', tamperSignature, false],
  ])('同一 iss の %s を上限件数ぶん並べても発行者 DID の解決は 1 回だけ', async (_name, mutate, valid) => {
    let body = '';
    const wallet = await createWallet({
      storage: new MemoryStorage(),
      didConfigurationFetchImpl: () =>
        Promise.resolve(
          new Response(body, { status: 200, headers: { 'content-type': 'application/json' } }),
        ),
    });
    await wallet.importMnemonic(TEST_MNEMONIC);
    const persona = await wallet.createPersona();
    await wallet.setActivePersona(persona.id);
    const jwt = (await wallet.generateDIDConfiguration(persona.did, ORIGIN))
      .linked_dids[0] as string;
    body = JSON.stringify({
      linked_dids: Array.from({ length: MAX_LINKED_DIDS }, () => mutate(jwt)),
    });
    const spy = spyOn(MethodKey.prototype, 'resolve');
    try {
      const result = await wallet.verifyDIDConfiguration(ORIGIN);
      expect(result.linkedDIDs).toHaveLength(MAX_LINKED_DIDS);
      expect(result.linkedDIDs.every((entry) => entry.valid === valid)).toBe(true);
      expect(spy).toHaveBeenCalledTimes(1);
    } finally {
      spy.mockRestore();
    }
  });
});
