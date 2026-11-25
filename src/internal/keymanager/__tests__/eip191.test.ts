/**
 * EIP-191 署名 / ES256K-R（IANA JWS alg 登録外の標準外の例外）のプリミティブ。
 *
 * - 署名は viem の `signMessage`（EIP-191 `personal_sign`）と同じバイト列になる（実ウォレット互換）。
 * - 署名から復元したアドレスが一致するときだけ検証に通る。署名・メッセージ・アドレスのどれを替えても通らない。
 * - 正準でない署名（high-S・recovery が 0 / 1 以外・長さ違い）は通らない。
 * - JWS の signing-input を `personal_sign` へ渡す偽造は検出される。
 */

import { describe, expect, it } from 'bun:test';
import { keccak_256 } from '@noble/hashes/sha3.js';
import { base64urlnopad } from '@scure/base';
import { privateKeyToAccount } from 'viem/accounts';
import {
  eip191Digest,
  ethereumAddressOfJwk,
  ethereumAddressOfPublicKey,
  looksLikeEs256kRSigningInput,
  recoverEip191PublicKey,
  signEip191,
  verifyEip191Address,
  verifyEip191PublicKey,
} from '../eip191.js';
import { getSecp256k1PublicKey } from '../signer.js';

const PRIVATE_KEY = new Uint8Array(32).fill(21);
const PUBLIC_KEY = getSecp256k1PublicKey(PRIVATE_KEY, false);
const ADDRESS = ethereumAddressOfPublicKey(PUBLIC_KEY);
const MESSAGE = new TextEncoder().encode('Sign in to Example\n日本語');

const SECP256K1_N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;

function hex(bytes: Uint8Array): `0x${string}` {
  return `0x${Buffer.from(bytes).toString('hex')}`;
}

describe('signEip191 / verifyEip191Address', () => {
  it('viem の signMessage（personal_sign）と同じアドレス・同じ署名（v = 27 + recovery）', async () => {
    const account = privateKeyToAccount(hex(PRIVATE_KEY));
    expect(ADDRESS).toBe(account.address.toLowerCase());
    const signature = signEip191(MESSAGE, PRIVATE_KEY);
    expect(signature).toHaveLength(65);
    const viemSignature = await account.signMessage({ message: { raw: MESSAGE } });
    // viem は r ‖ s ‖ v（v = 27 / 28）。本実装は r ‖ s ‖ recovery（0 / 1）。
    expect(viemSignature.slice(0, 130)).toBe(hex(signature).slice(0, 130));
    expect(Number.parseInt(viemSignature.slice(130), 16) - 27).toBe(signature[64] as number);
  });

  it('署名したアドレス（大文字小文字を問わない）だけが通る', () => {
    const signature = signEip191(MESSAGE, PRIVATE_KEY);
    expect(verifyEip191Address(MESSAGE, signature, ADDRESS)).toBe(true);
    expect(verifyEip191Address(MESSAGE, signature, ADDRESS.toUpperCase().replace('0X', '0x'))).toBe(
      true,
    );
    const other = ethereumAddressOfPublicKey(
      getSecp256k1PublicKey(new Uint8Array(32).fill(22), false),
    );
    expect(verifyEip191Address(MESSAGE, signature, other)).toBe(false);
  });

  it('メッセージ・署名のどのバイトを替えても通らない', () => {
    const signature = signEip191(MESSAGE, PRIVATE_KEY);
    const tampered = MESSAGE.slice();
    tampered[0] = (tampered[0] as number) ^ 1;
    expect(verifyEip191Address(tampered, signature, ADDRESS)).toBe(false);
    for (const index of [0, 31, 32, 63, 64]) {
      const broken = signature.slice();
      broken[index] = (broken[index] as number) ^ 1;
      expect(verifyEip191Address(MESSAGE, broken, ADDRESS)).toBe(false);
    }
  });

  it('EIP-191 のプレフィックスを持たない署名（生 keccak256 への署名）は通らない（ドメイン分離）', async () => {
    const account = privateKeyToAccount(hex(PRIVATE_KEY));
    // `eip191Digest` に対する署名は通る（同じダイジェスト）。メッセージそのものの keccak256 への署名は通らない。
    const prefixed = await account.sign({ hash: hex(eip191Digest(MESSAGE)) });
    expect(prefixed.slice(0, 130)).toBe(hex(signEip191(MESSAGE, PRIVATE_KEY)).slice(0, 130));
    const unprefixed = await account.sign({ hash: hex(keccak_256(MESSAGE)) });
    const bytes = Buffer.from(unprefixed.slice(2, 130), 'hex');
    const signature = new Uint8Array(65);
    signature.set(bytes);
    signature[64] = Number.parseInt(unprefixed.slice(130), 16) - 27;
    expect(verifyEip191Address(MESSAGE, signature, ADDRESS)).toBe(false);
  });

  it('正準でない署名は通らない: 長さ違い・recovery が 0 / 1 以外・high-S', () => {
    const signature = signEip191(MESSAGE, PRIVATE_KEY);
    expect(verifyEip191Address(MESSAGE, signature.subarray(0, 64), ADDRESS)).toBe(false);
    expect(verifyEip191Address(MESSAGE, new Uint8Array(66), ADDRESS)).toBe(false);
    for (const recovery of [2, 27, 28]) {
      const broken = signature.slice();
      broken[64] = recovery;
      expect(verifyEip191Address(MESSAGE, broken, ADDRESS)).toBe(false);
    }
    // s → n − s（high-S）と recovery の反転は、同じ鍵を復元する可鍛性のある署名。
    const s = BigInt(`0x${Buffer.from(signature.subarray(32, 64)).toString('hex')}`);
    const highS = signature.slice();
    highS.set(Buffer.from((SECP256K1_N - s).toString(16).padStart(64, '0'), 'hex'), 32);
    highS[64] = (signature[64] as number) ^ 1;
    expect(verifyEip191Address(MESSAGE, highS, ADDRESS)).toBe(false);
  });
});

describe('recoverEip191PublicKey / verifyEip191PublicKey', () => {
  it('署名者の公開鍵を復元でき、その公開鍵（圧縮・非圧縮）で検証できる', () => {
    const signature = signEip191(MESSAGE, PRIVATE_KEY);
    expect(recoverEip191PublicKey(MESSAGE, signature)).toEqual(PUBLIC_KEY);
    expect(verifyEip191PublicKey(MESSAGE, signature, PUBLIC_KEY)).toBe(true);
    expect(
      verifyEip191PublicKey(MESSAGE, signature, getSecp256k1PublicKey(PRIVATE_KEY, true)),
    ).toBe(true);
    expect(
      verifyEip191PublicKey(
        MESSAGE,
        signature,
        getSecp256k1PublicKey(new Uint8Array(32).fill(3), false),
      ),
    ).toBe(false);
  });

  it('復元できない署名は undefined', () => {
    expect(recoverEip191PublicKey(MESSAGE, new Uint8Array(65))).toBeUndefined();
    expect(recoverEip191PublicKey(MESSAGE, new Uint8Array(10))).toBeUndefined();
  });
});

describe('ethereumAddressOfJwk', () => {
  it('公開鍵 JWK の座標からアドレスを求める。座標が不正なら undefined', () => {
    const x = base64urlnopad.encode(PUBLIC_KEY.subarray(1, 33));
    const y = base64urlnopad.encode(PUBLIC_KEY.subarray(33, 65));
    expect(ethereumAddressOfJwk(x, y)).toBe(ADDRESS);
    expect(ethereumAddressOfJwk(x, undefined)).toBeUndefined();
    expect(ethereumAddressOfJwk(x, 'AAAA')).toBeUndefined();
    expect(ethereumAddressOfJwk('***', y)).toBeUndefined();
  });
});

describe('looksLikeEs256kRSigningInput（personal_sign 経由の JWS 偽造の検出）', () => {
  const segment = (value: unknown) =>
    base64urlnopad.encode(new TextEncoder().encode(JSON.stringify(value)));

  it('alg が ES256K-R の JWS ヘッダで始まる入力を検出する', () => {
    const input = new TextEncoder().encode(
      `${segment({ alg: 'ES256K-R', kid: 'did:pkh:eip155:1:0xabc#blockchainAccountId' })}.${segment({ iss: 'did:pkh:eip155:1:0xabc' })}`,
    );
    expect(looksLikeEs256kRSigningInput(input)).toBe(true);
  });

  it('ヘッダを水増しして長くしても検出する（長さで迂回できない）', () => {
    const input = new TextEncoder().encode(
      `${segment({ alg: 'ES256K-R', pad: 'A'.repeat(100_000) })}.${segment({})}`,
    );
    expect(looksLikeEs256kRSigningInput(input)).toBe(true);
  });

  it('通常のメッセージ・ほかの alg・壊れた入力は検出しない', () => {
    const encode = (text: string) => new TextEncoder().encode(text);
    expect(looksLikeEs256kRSigningInput(encode('Sign in to Example'))).toBe(false);
    expect(looksLikeEs256kRSigningInput(encode('example.com wants you to sign in.'))).toBe(false);
    expect(
      looksLikeEs256kRSigningInput(encode(`${segment({ alg: 'ES256K' })}.${segment({})}`)),
    ).toBe(false);
    expect(looksLikeEs256kRSigningInput(encode(`${segment(['ES256K-R'])}.x`))).toBe(false);
    expect(looksLikeEs256kRSigningInput(encode('.payload'))).toBe(false);
    expect(looksLikeEs256kRSigningInput(new Uint8Array([0xff, 0x2e, 0x00]))).toBe(false);
    expect(looksLikeEs256kRSigningInput(new Uint8Array())).toBe(false);
  });
});
