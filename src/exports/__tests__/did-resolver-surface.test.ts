/**
 * 公開エントリ（`src/index.ts`）の DID 解決面の pin。
 *
 * `Wallet` を作らずに `Wallet.resolveDID` と同じ DID メソッド一式を持つ Resolver を構築できること
 * （`createDidResolver`）。拡張機能のように DID 解決だけを行う利用者が、メソッド登録を書き写さずに済む。
 */

import { describe, expect, it } from 'bun:test';
import { createDidResolver, Resolver } from '../../index.js';

describe('公開エクスポート: createDidResolver', () => {
  it('公開エントリから Resolver を構築でき、did:key を解決できる', async () => {
    const resolver = createDidResolver();
    expect(resolver).toBeInstanceOf(Resolver);
    const did = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK';
    expect((await resolver.resolve(did)).id).toBe(did);
  });
});
