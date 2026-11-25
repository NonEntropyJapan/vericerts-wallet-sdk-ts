/**
 * createDidKey のエンコード検証。
 *
 * Ed25519 は W3C did:key Method spec の Test Vector で DID 文字列の完全一致を確認する。
 * secp256k1 / P-256 は DID プレフィックス（zQ3s / zDn）を確認する。
 */

import { describe, expect, it } from 'bun:test';
import { getP256PublicKey, getSecp256k1PublicKey } from '../../keymanager/signer.js';
import { createDidKey } from '../method-key.js';

/**
 * W3C did:key Method spec の Ed25519 Test Vector。
 *
 * DID 文字列から公開鍵を逆算せず、当該ベクターの 32B raw 公開鍵をリテラルでハードコードし、
 * `createDidKey` が期待 DID 文字列を生成することを独立検証する（半循環の解消）。
 * 出典: W3C did:key Method spec Test Vectors（公開鍵 hex 2e6fcce3...70e6）。
 */
const W3C_ED25519_DID = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK';
const W3C_ED25519_PUBLIC_KEY = Uint8Array.from([
  0x2e, 0x6f, 0xcc, 0xe3, 0x67, 0x01, 0xdc, 0x79, 0x14, 0x88, 0xe0, 0xd0, 0xb1, 0x74, 0x5c, 0xc1,
  0xe3, 0x3a, 0x4c, 0x1c, 0x9f, 0xcc, 0x41, 0xc6, 0x3b, 0xd3, 0x43, 0xdb, 0xbe, 0x09, 0x70, 0xe6,
]);

describe('createDidKey (encode)', () => {
  it('Ed25519 W3C ベクターで DID 文字列が完全一致する', () => {
    const doc = createDidKey('Ed25519', W3C_ED25519_PUBLIC_KEY);
    expect(doc.id).toBe(W3C_ED25519_DID);
  });

  it('secp256k1 は did:key:zQ3s... プレフィックスを持つ', () => {
    // 既知秘密鍵から圧縮 33B 公開鍵を導出する。
    const privateKey = new Uint8Array(32).fill(1);
    const publicKey = getSecp256k1PublicKey(privateKey, true);
    const doc = createDidKey('secp256k1', publicKey);
    expect(doc.id.startsWith('did:key:zQ3s')).toBe(true);
  });

  it('P-256 は did:key:zDn... プレフィックスを持つ', () => {
    const privateKey = new Uint8Array(32).fill(2);
    const publicKey = getP256PublicKey(privateKey, true);
    const doc = createDidKey('P-256', publicKey);
    expect(doc.id.startsWith('did:key:zDn')).toBe(true);
  });
});
