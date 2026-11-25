/**
 * `createWallet` / `buildResolver` / `DidFacade` の呼び出しオプションの `Object.prototype` 汚染耐性テスト
 *
 * `rpcUrls` / `ipfsGatewayUrl` / `ipfsApiUrl` / `didNodeUrls` / `kdf` および `createDID` の `keyID`、`signAsDelegate` の
 * `delegatedDid` / `data` / `scope` / `grantedScopes` は、省略しても鎖読みで汚染値が入ってはならない。
 * 値の取り込みを getter の呼び出しで検出する（own 限定で読めば getter は一度も呼ばれない）。
 */

import { describe, expect, it } from 'bun:test';
import { withPollutedPrototypeAccessorAsync } from '../../../internal/__tests__/prototype-pollution.fixtures.js';
import { ethereumPath } from '../../../internal/keymanager/hd.js';
import { MemoryStorage } from '../../../storage/storage.js';
import { createWallet } from '../../factory.js';

const TEST_MNEMONIC =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

/** 指定キーを getter で汚染し、読まれたキーを記録する。 */
function spyGetters(keys: readonly string[], read: string[]): Record<string, () => unknown> {
  return Object.fromEntries(
    keys.map((key) => [
      key,
      () => {
        read.push(key);
        return undefined;
      },
    ]),
  );
}

describe('createWallet / buildResolver のオプション読みは own 限定', () => {
  it('省略した rpcUrls / ipfsGatewayUrl / ipfsApiUrl / didNodeUrls / kdf を継承値から読まない', async () => {
    const read: string[] = [];
    await withPollutedPrototypeAccessorAsync(
      spyGetters(['rpcUrls', 'ipfsGatewayUrl', 'ipfsApiUrl', 'didNodeUrls', 'kdf'], read),
      async () => {
        const wallet = await createWallet({ storage: new MemoryStorage() });
        await wallet.importMnemonic(TEST_MNEMONIC);
      },
    );
    expect(read).toEqual([]);
  });
});

describe('DidFacade の入力読みは own 限定', () => {
  it('createDID は省略した keyID を継承値から読まない', async () => {
    const wallet = await createWallet({ storage: new MemoryStorage() });
    await wallet.importMnemonic(TEST_MNEMONIC);
    await wallet.deriveKey(ethereumPath(0, 0));
    const read: string[] = [];
    await withPollutedPrototypeAccessorAsync(spyGetters(['keyID'], read), () =>
      wallet.createDID('key', {}),
    );
    expect(read).toEqual([]);
  });
});
