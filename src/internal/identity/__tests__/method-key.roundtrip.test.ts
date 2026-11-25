/**
 * secp256k1 / P-256 の create → resolve ラウンドトリップ検証。
 *
 * keymanager の公開鍵導出（既知秘密鍵）で得た圧縮 33B 公開鍵を createDidKey で符号化し、
 * resolveDidKey の publicKeyMultibase を multibase デコード→prefix 除去すると
 * 元公開鍵に一致することを確認する。VerificationMethod type も検証する。
 */

import { describe, expect, it } from 'bun:test';
import { getP256PublicKey, getSecp256k1PublicKey } from '../../keymanager/signer.js';
import type { DidKeyType } from '../did.js';
import { createDidKey, resolveDidKey } from '../method-key.js';
import { multibaseBase58Decode } from '../multibase.js';

/** ラウンドトリップ検証ケース（鍵タイプ・公開鍵導出・期待 VM type）。 */
const cases: ReadonlyArray<{
  readonly keyType: DidKeyType;
  readonly publicKey: Uint8Array;
  readonly vmType: string;
}> = [
  {
    keyType: 'secp256k1',
    publicKey: getSecp256k1PublicKey(new Uint8Array(32).fill(3), true),
    vmType: 'EcdsaSecp256k1VerificationKey2019',
  },
  {
    keyType: 'P-256',
    publicKey: getP256PublicKey(new Uint8Array(32).fill(4), true),
    vmType: 'Multikey',
  },
];

describe('createDidKey → resolveDidKey roundtrip', () => {
  for (const { keyType, publicKey, vmType } of cases) {
    it(`${keyType}: 公開鍵が往復で一致し VM type が ${vmType}`, () => {
      const created = createDidKey(keyType, publicKey);
      const resolved = resolveDidKey(created.id);

      // VerificationMethod type を確認する。
      expect(resolved.verificationMethod[0]?.type).toBe(vmType);

      // publicKeyMultibase をデコード → prefix(2B) 除去 → 元公開鍵に一致。
      const multibase = resolved.verificationMethod[0]?.publicKeyMultibase ?? '';
      const decoded = multibaseBase58Decode(multibase);
      const recoveredPublicKey = decoded.subarray(2);
      expect(Array.from(recoveredPublicKey)).toEqual(Array.from(publicKey));
    });
  }
});
