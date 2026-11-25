/**
 * did:ebsi の DID 形式・ローカル生成・鍵名の検証。
 */

import { describe, expect, it } from 'bun:test';
import { createHash } from 'node:crypto';
import { ErrorCodes } from '../../../errors.js';
import {
  ed25519Jwk,
  expectThrows,
  p256Jwk,
  secp256k1Jwk,
} from '../../__tests__/network-method.fixtures.js';
import { ebsiKeyName, generateDidEbsi, parseDidEbsi } from '../did-ebsi.js';
import { DID } from './ebsi.fixtures.js';

describe('parseDidEbsi / generateDidEbsi / ebsiKeyName', () => {
  it('仕様の例（省略形・バージョン 1）を受理する', () => {
    expect(parseDidEbsi(DID).identifier).toBe('zvHWX359A3CvfJnCYaAiAde');
  });

  it('generateDidEbsi は version 1 + 乱数 16 バイトで、生成した DID を parse できる', () => {
    const random = Uint8Array.from({ length: 16 }, (_, i) => i + 1);
    const { did } = generateDidEbsi({ randomBytes: () => random });
    expect(did.startsWith('did:ebsi:z')).toBe(true);
    expect(parseDidEbsi(did).identifier).toBe(did.slice('did:ebsi:'.length));
    // 乱数源が同じなら同じ DID（ローカル生成のみで副作用がない）。
    expect(generateDidEbsi({ randomBytes: () => random }).did).toBe(did);
    // 既定の乱数源でも別々の DID になる。
    expect(generateDidEbsi().did).not.toBe(generateDidEbsi().did);
  });

  it('乱数源が 16 バイトでなければ 2001', () => {
    expectThrows(
      () => generateDidEbsi({ randomBytes: () => new Uint8Array(8) }),
      ErrorCodes.INVALID_DID,
    );
  });

  it('network 付き・バージョンバイトが 1 以外は 2001 ebsi_unsupported_form', () => {
    expectThrows(
      () => parseDidEbsi(`did:ebsi:test:${DID.slice(9)}`),
      ErrorCodes.INVALID_DID,
      'ebsi_unsupported_form',
    );
    const version2 = generateDidEbsi({ randomBytes: () => new Uint8Array(16) }).did;
    expect(version2).toBeDefined();
    // バージョンバイトを 2 に差し替えた識別子（17 バイトの先頭を 2 にして符号化）。
    const bytes = new Uint8Array(17);
    bytes[0] = 2;
    const identifier = `z${encodeBase58(bytes)}`;
    expectThrows(
      () => parseDidEbsi(`did:ebsi:${identifier}`),
      ErrorCodes.INVALID_DID,
      'ebsi_unsupported_form',
    );
  });

  it('形式不正（接頭辞・multibase・長さ・文字種）は 2001 ebsi_invalid_identifier', () => {
    for (const bad of [
      'did:web:example.com',
      'did:ebsi:',
      'did:ebsi:zzz',
      'did:ebsi:vHWX359A3CvfJnCYaAiAde',
      'did:ebsi:z0OIl',
      `did:ebsi:z${'1'.repeat(64)}`,
    ]) {
      expectThrows(() => parseDidEbsi(bad), ErrorCodes.INVALID_DID, 'ebsi_invalid_identifier');
    }
  });

  it('ebsiKeyName は RFC 7638 の JWK Thumbprint（crv, kty, x, y の辞書順）', () => {
    const jwk = p256Jwk(7);
    const canonical = JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y });
    const expected = createHash('sha256').update(canonical).digest('base64url');
    expect(ebsiKeyName(jwk)).toBe(expected);
    // 余分なメンバ（kid / use）は結果に影響しない。
    expect(ebsiKeyName({ ...jwk, kid: 'x', use: 'sig' })).toBe(expected);
    expect(ebsiKeyName(secp256k1Jwk(7))).not.toBe(expected);
  });

  it('ebsiKeyName は Ed25519 / 座標不正を 2010 ebsi_key_unsupported で拒否する', () => {
    expectThrows(
      () => ebsiKeyName(ed25519Jwk()),
      ErrorCodes.DID_DOC_INVALID,
      'ebsi_key_unsupported',
    );
    expectThrows(
      () => ebsiKeyName({ ...p256Jwk(), x: 'AAAA' }),
      ErrorCodes.DID_DOC_INVALID,
      'ebsi_key_unsupported',
    );
  });
});

/** バイト列を base58btc（Bitcoin alphabet）にする（テスト内で独立に実装して往復を確かめる）。 */
function encodeBase58(bytes: Uint8Array): string {
  const alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
  let value = 0n;
  for (const byte of bytes) {
    value = value * 256n + BigInt(byte);
  }
  let out = '';
  while (value > 0n) {
    out = alphabet[Number(value % 58n)] + out;
    value /= 58n;
  }
  for (const byte of bytes) {
    if (byte !== 0) {
      break;
    }
    out = `1${out}`;
  }
  return out;
}
