/**
 * `verifyCertificateChain` の RSA 鍵長検査。
 *
 * issuer（中間 CA / Trust Anchor）の RSA 鍵が 2048bit 未満だと、その鍵による証明書署名の検証
 * （`verifySignature`）が拒否されるため、署名が数学的に正しくてもチェーンは `trusted: false` になる。
 * 新しいエラーコードは無い。2048bit の issuer は従来どおり信頼されることを併置する。
 */

import { describe, expect, test } from 'bun:test';
import { generateKeyPairSync } from 'node:crypto';
import { verifyCertificateChain } from '../../chain.js';
import { makeCertificate } from '../fixtures.js';

/** 指定ビット長の RSA 鍵を持つ自己署名 Root CA。 */
function rsaRoot(modulusLength: number): ReturnType<typeof makeCertificate> {
  const { privateKey } = generateKeyPairSync('rsa', { modulusLength });
  return makeCertificate({ cn: 'Root CA', kind: 'rsa', subjectKey: privateKey });
}

describe('verifyCertificateChain: issuer の RSA 鍵長', () => {
  test('2048bit の Root が直接発行した leaf は信頼する（対照）', async () => {
    const root = rsaRoot(2048);
    const leaf = makeCertificate({
      cn: 'Issuer',
      kind: 'ec',
      issuer: { name: root.subjectName, privateKey: root.privateKey, kind: 'rsa' },
    });
    const result = await verifyCertificateChain(leaf.der, [], { trustAnchorsDer: [root.der] });
    expect(result.trusted).toBe(true);
  });

  test('1024bit の Root が署名した leaf は trusted:false', async () => {
    const root = rsaRoot(1024);
    const leaf = makeCertificate({
      cn: 'Issuer',
      kind: 'ec',
      issuer: { name: root.subjectName, privateKey: root.privateKey, kind: 'rsa' },
    });
    const result = await verifyCertificateChain(leaf.der, [], { trustAnchorsDer: [root.der] });
    expect(result.trusted).toBe(false);
  });

  test('1024bit の中間 CA が署名した leaf は trusted:false（Root は 2048bit）', async () => {
    const root = rsaRoot(2048);
    const { privateKey: weakKey } = generateKeyPairSync('rsa', { modulusLength: 1024 });
    const inter = makeCertificate({
      cn: 'Intermediate CA',
      kind: 'rsa',
      ca: true,
      keyUsage: ['keyCertSign'],
      subjectKey: weakKey,
      issuer: { name: root.subjectName, privateKey: root.privateKey, kind: 'rsa' },
    });
    const leaf = makeCertificate({
      cn: 'Issuer',
      kind: 'ec',
      issuer: { name: inter.subjectName, privateKey: inter.privateKey, kind: 'rsa' },
    });
    const result = await verifyCertificateChain(leaf.der, [inter.der], {
      trustAnchorsDer: [root.der],
    });
    expect(result.trusted).toBe(false);
  });
});
