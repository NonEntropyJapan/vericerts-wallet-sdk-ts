/**
 * Resolver のディスパッチ検証。
 *
 * MethodKey 登録後の did:key 解決、未登録メソッド（did:web）→ 2002、
 * did: 形式違反 → 2001 を確認する。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../errors.js';
import { MethodKey } from '../method-key.js';
import { Resolver } from '../resolver.js';

/** W3C did:key Method spec の Ed25519 Test Vector DID。 */
const W3C_ED25519_DID = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK';

describe('Resolver', () => {
  it('MethodKey 登録後に did:key を解決する', async () => {
    const resolver = new Resolver();
    resolver.register(new MethodKey());
    const doc = await resolver.resolve(W3C_ED25519_DID);
    expect(doc.id).toBe(W3C_ED25519_DID);
    expect(doc.verificationMethod[0]?.type).toBe('Ed25519VerificationKey2020');
  });

  it('未登録メソッド（did:web）は 2002 を投げる', async () => {
    const resolver = new Resolver();
    resolver.register(new MethodKey());
    await expect(resolver.resolve('did:web:example.com')).rejects.toThrow(
      new VericertsError(ErrorCodes.METHOD_NOT_SUPPORTED),
    );
  });

  it('did: 形式違反は 2001 を投げる', async () => {
    const resolver = new Resolver();
    resolver.register(new MethodKey());
    await expect(resolver.resolve('not-a-did')).rejects.toThrow(
      new VericertsError(ErrorCodes.INVALID_DID),
    );
  });

  it('method 部はあるが identifier がない場合は 2001', async () => {
    const resolver = new Resolver();
    resolver.register(new MethodKey());
    await expect(resolver.resolve('did:key:')).rejects.toThrow(
      new VericertsError(ErrorCodes.INVALID_DID),
    );
  });
});
