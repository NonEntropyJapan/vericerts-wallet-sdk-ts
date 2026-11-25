/**
 * `didcomm/jwe.ts` の JWE Compact Serialization（ECDH-ES+A256KW / A256GCM）ラウンドトリップと
 * 失敗面のテスト。
 */

import { describe, expect, it } from 'bun:test';
import { p256 } from '@noble/curves/nist.js';
import { base64urlnopad } from '@scure/base';
import { VericertsError } from '../../errors.js';
import { DIDCOMM_PLAIN_CTY, decryptDidCommJwe, encryptDidCommJwe } from '../jwe.js';

function generateP256KeyAgreementKey(seed: number): {
  privateKey: Uint8Array;
  publicKeyJwk: Record<string, string>;
} {
  const privateKey = new Uint8Array(32).fill(seed);
  const uncompressed = p256.getPublicKey(privateKey, false);
  return {
    privateKey,
    publicKeyJwk: {
      kty: 'EC',
      crv: 'P-256',
      x: base64urlnopad.encode(uncompressed.slice(1, 33)),
      y: base64urlnopad.encode(uncompressed.slice(33)),
    },
  };
}

describe('encryptDidCommJwe / decryptDidCommJwe', () => {
  it('平文を暗号化し、対応する秘密鍵で元通り復号できる', async () => {
    const recipient = generateP256KeyAgreementKey(1);
    const jwe = await encryptDidCommJwe('{"hello":"world"}', recipient.publicKeyJwk, {
      kid: 'did:peer:2.xyz#key-2',
      cty: DIDCOMM_PLAIN_CTY,
    });

    // JWE Compact Serialization は 5 セグメント。
    expect(jwe.split('.').length).toBe(5);

    const result = await decryptDidCommJwe(jwe, recipient.privateKey);
    expect(result.plaintext).toBe('{"hello":"world"}');
    expect(result.cty).toBe(DIDCOMM_PLAIN_CTY);
    expect(result.kid).toBe('did:peer:2.xyz#key-2');
  });

  it('対応しない秘密鍵での復号は DIDCOMM_UNPACK_FAILED（鍵不一致）で失敗する', async () => {
    const recipient = generateP256KeyAgreementKey(2);
    const wrongPrivateKey = new Uint8Array(32).fill(99);
    const jwe = await encryptDidCommJwe('secret', recipient.publicKeyJwk);

    await expect(decryptDidCommJwe(jwe, wrongPrivateKey)).rejects.toMatchObject({
      code: '9002',
    });
  });

  it('セグメント数が不正な JWE は DIDCOMM_UNPACKING_FAILED（構造不正）で失敗する', async () => {
    const recipient = generateP256KeyAgreementKey(3);
    await expect(decryptDidCommJwe('a.b.c', recipient.privateKey)).rejects.toMatchObject({
      code: '9004',
    });
  });

  it('protected header が非対応の alg/enc の場合 DIDCOMM_UNPACKING_FAILED で失敗する', async () => {
    const recipient = generateP256KeyAgreementKey(4);
    const badHeader = base64urlnopad.encode(
      new TextEncoder().encode(JSON.stringify({ alg: 'dir', enc: 'A256GCM', epk: {} })),
    );
    const tampered = [badHeader, 'AA', 'AA', 'AA', 'AA'].join('.');
    let caught: unknown;
    try {
      await decryptDidCommJwe(tampered, recipient.privateKey);
    } catch (error) {
      caught = error;
    }
    expect(caught).toBeInstanceOf(VericertsError);
    expect((caught as VericertsError).code).toBe('9004');
  });

  it('protected header が JSON null / 配列 / プリミティブの JWE は TypeError ではなく 9004', async () => {
    const recipient = generateP256KeyAgreementKey(5);
    for (const json of ['null', '1', '[]', '"x"', 'true']) {
      const seg = base64urlnopad.encode(new TextEncoder().encode(json));
      const jwe = [seg, 'AA', 'AA', 'AA', base64urlnopad.encode(new Uint8Array(16))].join('.');
      await expect(decryptDidCommJwe(jwe, recipient.privateKey)).rejects.toMatchObject({
        code: '9004',
      });
    }
  });

  it('受信者鍵が P-256 でない場合、暗号化前段で DIDCOMM_PACKING_FAILED が送出される', async () => {
    const nonP256Jwk = {
      kty: 'OKP',
      crv: 'Ed25519',
      x: base64urlnopad.encode(new Uint8Array(32).fill(5)),
    };
    await expect(encryptDidCommJwe('data', nonP256Jwk)).rejects.toMatchObject({ code: '9003' });
  });
});
