/**
 * Wallet ファサードの DID メソッド追加登録の統合テスト。
 *
 * `createWallet` が登録する DID メソッド一式は `wallet.resolve-methods.test.ts` が担う。
 * 本ファイルは「利用者が生成後にカスタム `DIDMethod` を追加登録でき、以降 `resolveDID` が当該
 * プラグインへディスパッチする」という配線のみを検証する。
 *
 * 判定方法: 登録前は Resolver が未登録メソッドとして 2002 で reject し、登録後はプラグインが
 * 返す固定 DID Document がそのまま得られる（ネットワーク非依存）。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../../internal/errors.js';
import type { DIDDocument, DIDMethod } from '../../../internal/identity/did.js';
import { MemoryStorage } from '../../../storage/storage.js';
import { createWallet } from '../../factory.js';

/** カスタム DID メソッドが返す固定の DID Document。 */
const STUB_DOCUMENT: DIDDocument = {
  '@context': ['https://www.w3.org/ns/did/v1'],
  id: 'did:stub:abc',
  verificationMethod: [],
  authentication: [],
  assertionMethod: [],
};

/** 本テストでは呼ばれない想定の `DIDMethod` メンバ用スタブ reject。 */
const unused = (): Promise<never> => Promise.reject(new Error('unused stub method called in test'));

/** resolve だけを実装したカスタム DID メソッド（登録の配線確認用）。 */
const STUB_METHOD: DIDMethod = {
  method: () => 'stub',
  create: unused,
  resolve: () => Promise.resolve(STUB_DOCUMENT),
  update: unused,
  deactivate: unused,
};

describe('Wallet.registerDIDMethod', () => {
  it('登録前の did:stub は METHOD_NOT_SUPPORTED(2002)', async () => {
    const wallet = await createWallet({ storage: new MemoryStorage() });
    await expect(wallet.resolveDID('did:stub:abc')).rejects.toThrow(
      new VericertsError(ErrorCodes.METHOD_NOT_SUPPORTED),
    );
  });

  it('登録後は resolveDID が当該プラグインへディスパッチする', async () => {
    const wallet = await createWallet({ storage: new MemoryStorage() });
    expect(wallet.registerDIDMethod(STUB_METHOD)).toBeUndefined();
    expect(await wallet.resolveDID('did:stub:abc')).toEqual(STUB_DOCUMENT);
  });

  it('同名メソッドの再登録は上書きする', async () => {
    const wallet = await createWallet({ storage: new MemoryStorage() });
    wallet.registerDIDMethod(STUB_METHOD);
    const overridden: DIDDocument = { ...STUB_DOCUMENT, id: 'did:stub:overridden' };
    wallet.registerDIDMethod({ ...STUB_METHOD, resolve: () => Promise.resolve(overridden) });
    expect((await wallet.resolveDID('did:stub:abc')).id).toBe('did:stub:overridden');
  });

  it('登録は当該 Wallet インスタンスに閉じる（別インスタンスへ漏れない）', async () => {
    const wallet = await createWallet({ storage: new MemoryStorage() });
    wallet.registerDIDMethod(STUB_METHOD);
    const other = await createWallet({ storage: new MemoryStorage() });
    await expect(other.resolveDID('did:stub:abc')).rejects.toThrow(
      new VericertsError(ErrorCodes.METHOD_NOT_SUPPORTED),
    );
  });
});
