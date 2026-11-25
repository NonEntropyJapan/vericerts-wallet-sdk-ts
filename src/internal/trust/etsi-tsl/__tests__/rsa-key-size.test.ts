/**
 * RSA 公開鍵の modulus 長検査（RSA は 2048 bit 以上）。
 *
 * `rsaModulusBitLength`（SPKI → modulus ビット長）と、それを入口で使う `verifySignature` の境界
 * （2047 拒否 / 2048 受理 / 4096 受理 / 1024 拒否 / 壊れた SPKI 拒否 / ECDSA 非影響）を固定する。
 */

import { describe, expect, test } from 'bun:test';
import { createSign, generateKeyPairSync, type KeyObject } from 'node:crypto';
import { MIN_RSA_MODULUS_BITS, rsaModulusBitLength } from '../rsa-key-size.js';
import { verifySignature } from '../verify.js';

const DATA = new TextEncoder().encode('signed payload');

function spkiOf(key: KeyObject): Uint8Array {
  return new Uint8Array(key.export({ type: 'spki', format: 'der' }));
}

/**
 * 2047bit の実鍵（Node `generateKeyPairSync('rsa', { modulusLength: 2047 })` で生成した SPKI と、
 * `DATA` への RSASSA-PKCS1-v1_5-SHA256 署名）。Bun（BoringSSL）は 2047 を 1920 に丸めるため、
 * 境界値は生成せず固定値で持つ。
 */
const RSA_2047_SPKI = Buffer.from(
  'MIIBITANBgkqhkiG9w0BAQEFAAOCAQ4AMIIBCQKCAQBdE4sy6sDJnf+9OgDmYFlcNzWxNbcrLQk0QwCiruPrYVwRqdO6zBUBNmJdIhfq8iztBVWRoFZ4/zUEN+aFokxDW6Aw5KpsTF276byhhkrrhzTtvmqZ/YFLW8SWgOiqHfgcc9VgQdZrf1+e8KLBIPjQwzsfE0n44/tX68JuNNZGh8P7wQ97pxysIQaev1rEZjhnrv0g00saWLZ7cEiBEH7Ji4DDBTe3RbUDLFdPHWSFiKApAAT1JR6MGyDPPwDfIVLjUzOsJoGl/WVVTmPfAf3tE+Nf9UuNUBVOa36EJ33mn4dXgjD9MMQmgeN0j8QI8H6VQSlW9n1aKGffQAzUNsOXAgMBAAE=',
  'base64',
);
const RSA_2047_SIGNATURE = Buffer.from(
  'UFN2HahoUm/dQDmtk8uYL8JJYMgCQy2ZOpxibhhJKG/3dh1RPxZPCsS/pOF1We6Ge4p+nalOVjSzyJRwqurox2oZMLOMITQcu2nj3Vtqe9zC15jk8qeVHhfq/gWfrmklWUHOLKjpqYvsvcwMB0r6yEx26ZAI2HFIrEBhu6/IFscv1pkb3uEyPz8xtBzwovbKEDqRs+GPOA77k8HvPyxyPA9AsD1f8nygoNy+DEqDnvPqSGzCScg9iRJzF4Aj6/JNFp+/Xew+ATMw+BpxJ932Pp/V9izLgqFVntxB89ZgQskZiDon8YZwP9+orKVs7u8ma32BuJS9m8agbylRAVNWoA==',
  'base64',
);

function rsaFixture(modulusLength: number): { spki: Uint8Array; signature: Uint8Array } {
  const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength });
  const signer = createSign('SHA256');
  signer.update(DATA);
  signer.end();
  return { spki: spkiOf(publicKey), signature: new Uint8Array(signer.sign(privateKey)) };
}

describe('rsaModulusBitLength', () => {
  test.each([1024, 2048, 3072, 4096])('%i bit 鍵の modulus 長を実ビット長で返す', (bits) => {
    const { publicKey } = generateKeyPairSync('rsa', { modulusLength: bits });
    expect(rsaModulusBitLength(spkiOf(publicKey))).toBe(bits);
  });

  test('2047bit の実鍵（固定 SPKI）は 2047 を返す', () => {
    expect(rsaModulusBitLength(new Uint8Array(RSA_2047_SPKI))).toBe(2047);
  });

  test('しきい値は 2048bit', () => {
    expect(MIN_RSA_MODULUS_BITS).toBe(2048);
  });

  test('切り詰めた SPKI は undefined', () => {
    const { publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
    const spki = spkiOf(publicKey);
    expect(rsaModulusBitLength(spki.subarray(0, spki.length - 10))).toBeUndefined();
    expect(rsaModulusBitLength(spki.subarray(0, 4))).toBeUndefined();
    expect(rsaModulusBitLength(new Uint8Array())).toBeUndefined();
  });

  test('末尾に余分なバイトが付いた SPKI は undefined', () => {
    const { publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
    const spki = spkiOf(publicKey);
    const padded = new Uint8Array(spki.length + 1);
    padded.set(spki);
    expect(rsaModulusBitLength(padded)).toBeUndefined();
  });

  test('RSA 以外の OID（EC P-256）の SPKI は undefined', () => {
    const { publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    expect(rsaModulusBitLength(spkiOf(publicKey))).toBeUndefined();
  });

  test('rsaEncryption 以外の OID（rsaesOaep）を載せた SPKI は undefined', () => {
    const { publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
    const spki = spkiOf(publicKey).slice();
    // OID 1.2.840.113549.1.1.1 の末尾 arc（0x01）を 0x07（rsaesOaep）に置き換える。
    const oidEnd = spki.findIndex((_, i) => spki[i] === 0x06 && spki[i + 1] === 0x09) + 10;
    expect(spki[oidEnd]).toBe(0x01);
    spki[oidEnd] = 0x07;
    expect(rsaModulusBitLength(spki)).toBeUndefined();
  });
  test('modulus が負数・0 の RSAPublicKey は undefined', () => {
    // SEQUENCE { SEQUENCE { OID rsaEncryption, NULL }, BIT STRING { 0, SEQUENCE { INTEGER m, INTEGER 3 } } }
    const algId = [
      0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00,
    ];
    const build = (modulus: number[]): Uint8Array => {
      const rsaKey = [
        0x30,
        modulus.length + 2 + 3,
        0x02,
        modulus.length,
        ...modulus,
        0x02,
        0x01,
        3,
      ];
      const bitString = [0x03, rsaKey.length + 1, 0x00, ...rsaKey];
      return Uint8Array.from([0x30, algId.length + bitString.length, ...algId, ...bitString]);
    };
    expect(rsaModulusBitLength(build([0x00, 0x80]))).toBe(8);
    expect(rsaModulusBitLength(build([0x80]))).toBeUndefined();
    expect(rsaModulusBitLength(build([0x00]))).toBeUndefined();
  });
});

describe('verifySignature: RSA 鍵長', () => {
  test('2048bit は受理する', async () => {
    const { spki, signature } = rsaFixture(2048);
    expect(await verifySignature('RSASSA-PKCS1-v1_5-SHA256', spki, signature, DATA)).toBe(true);
  });

  test('4096bit は受理する（上限は設けない）', async () => {
    const { spki, signature } = rsaFixture(4096);
    expect(await verifySignature('RSASSA-PKCS1-v1_5-SHA256', spki, signature, DATA)).toBe(true);
  });

  test('2047bit は署名が正しくても拒否する（鍵長以外は 2048bit と同条件）', async () => {
    const spki = new Uint8Array(RSA_2047_SPKI);
    const signature = new Uint8Array(RSA_2047_SIGNATURE);
    // 対照: 鍵長検査を通さず WebCrypto で直接検証すると署名は正しい（拒否理由が鍵長のみであることの確認）。
    const key = await crypto.subtle.importKey(
      'spki',
      spki,
      { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
      false,
      ['verify'],
    );
    expect(await crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, signature, DATA)).toBe(true);
    expect(await verifySignature('RSASSA-PKCS1-v1_5-SHA256', spki, signature, DATA)).toBe(false);
  });

  test('1024bit は署名が正しくても拒否する', async () => {
    const { spki, signature } = rsaFixture(1024);
    expect(await verifySignature('RSASSA-PKCS1-v1_5-SHA256', spki, signature, DATA)).toBe(false);
  });

  test('壊れた SPKI（切り詰め）は拒否する', async () => {
    const { spki, signature } = rsaFixture(2048);
    expect(
      await verifySignature(
        'RSASSA-PKCS1-v1_5-SHA256',
        spki.subarray(0, spki.length - 10),
        signature,
        DATA,
      ),
    ).toBe(false);
  });

  test('RSA 署名アルゴリズムに EC の SPKI を渡すと拒否する', async () => {
    const { publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    expect(
      await verifySignature(
        'RSASSA-PKCS1-v1_5-SHA256',
        spkiOf(publicKey),
        new Uint8Array(64),
        DATA,
      ),
    ).toBe(false);
  });

  test('ECDSA の経路は鍵長検査の影響を受けない', async () => {
    const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const signer = createSign('SHA256');
    signer.update(DATA);
    signer.end();
    const signature = new Uint8Array(signer.sign({ key: privateKey, dsaEncoding: 'ieee-p1363' }));
    expect(await verifySignature('ECDSA-P256-SHA256', spkiOf(publicKey), signature, DATA)).toBe(
      true,
    );
  });
});
