/**
 * did:peer numalgo 2 の `V` / `E` 鍵エレメントの検証テスト。
 *
 * `V` は Ed25519 / secp256k1 / P-256、`E` は P-256 / X25519 のみ。
 * multicodec 接頭辞・鍵の種類・鍵長が合わない鍵は、生成（`createDidPeer2`）でも解決（`resolveDidPeer`）でも
 * `2001`（INVALID_DID）で拒否する。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import { multibaseBase58Encode } from '../../multibase.js';
import { createDidPeer2, encodePublicKeyMultibase, resolveDidPeer } from '../method-peer.js';
import { multikey, p256Key, x25519Key } from './numalgo2-keys.fixtures.js';

const ED25519_KEY = encodePublicKeyMultibase('Ed25519', new Uint8Array(32).fill(1));
const SECP256K1_KEY = encodePublicKeyMultibase(
  'secp256k1',
  Uint8Array.from([2, ...new Array(32).fill(1)]),
);
const P256_KEY = p256Key(2);
const X25519_KEY = x25519Key(3);

/** 非 canonical varint（`0xed 0x81 0x00`）で Ed25519 の長さに合わせた鍵。 */
const NON_CANONICAL_ED25519 = multibaseBase58Encode(
  Uint8Array.from([0xed, 0x81, 0x00, ...new Array(31).fill(1)]),
);

function expectInvalidDid(fn: () => unknown): void {
  try {
    fn();
  } catch (e) {
    expect(e).toBeInstanceOf(VericertsError);
    expect((e as VericertsError).code).toBe(ErrorCodes.INVALID_DID);
    return;
  }
  throw new Error('did not throw');
}

/** 署名鍵 `V` として拒否されるべき鍵。 */
const INVALID_V_KEYS: ReadonlyArray<readonly [string, string]> = [
  ['X25519（署名に使えない）', X25519_KEY],
  ['未対応 multicodec（P-384 = 0x1201）', multikey(0x1201, new Uint8Array(49).fill(1))],
  ['Ed25519 の鍵長不足', multikey(0xed, new Uint8Array(31).fill(1))],
  ['Ed25519 の鍵長超過', multikey(0xed, new Uint8Array(33).fill(1))],
  ['secp256k1 の非圧縮 65B', multikey(0xe7, new Uint8Array(65).fill(1))],
  ['P-256 の 32B（鍵長不足）', multikey(0x1200, new Uint8Array(32).fill(1))],
  ['非 canonical varint', NON_CANONICAL_ED25519],
  ['multicodec 接頭辞無しの 32B', multibaseBase58Encode(new Uint8Array(32).fill(1))],
];

/** 暗号鍵 `E` として拒否されるべき鍵。 */
const INVALID_E_KEYS: ReadonlyArray<readonly [string, string]> = [
  ['Ed25519（署名専用）', ED25519_KEY],
  ['secp256k1', SECP256K1_KEY],
  ['X25519 の鍵長不足', multikey(0xec, new Uint8Array(31).fill(1))],
  ['X25519 の鍵長超過', multikey(0xec, new Uint8Array(33).fill(1))],
  ['P-256 の鍵長不足', multikey(0x1200, new Uint8Array(32).fill(1))],
  ['未対応 multicodec（P-384 = 0x1201）', multikey(0x1201, new Uint8Array(49).fill(1))],
];

describe('numalgo 2 の V 鍵検証', () => {
  it.each([
    ['Ed25519', ED25519_KEY],
    ['secp256k1', SECP256K1_KEY],
    ['P-256', P256_KEY],
  ])('%s は受理する（生成 → 解決）', (_name, key) => {
    const doc = resolveDidPeer(createDidPeer2({ verificationKeys: [key] }));
    expect(doc.verificationMethod[0]?.publicKeyMultibase).toBe(key);
  });

  it.each(INVALID_V_KEYS)('生成で拒否する: %s', (_name, key) => {
    expectInvalidDid(() => createDidPeer2({ verificationKeys: [key] }));
  });

  it.each(INVALID_V_KEYS)('解決で拒否する: %s', (_name, key) => {
    expectInvalidDid(() => resolveDidPeer(`did:peer:2.V${key}`));
  });
});

describe('numalgo 2 の E 鍵検証', () => {
  it.each([
    ['P-256', P256_KEY],
    ['X25519', X25519_KEY],
  ])('%s は受理する（生成 → 解決）', (_name, key) => {
    const doc = resolveDidPeer(
      createDidPeer2({ verificationKeys: [ED25519_KEY], keyAgreementKeys: [key] }),
    );
    expect(doc.keyAgreement).toHaveLength(1);
  });

  it.each(INVALID_E_KEYS)('生成で拒否する: %s', (_name, key) => {
    expectInvalidDid(() =>
      createDidPeer2({ verificationKeys: [ED25519_KEY], keyAgreementKeys: [key] }),
    );
  });

  it.each(INVALID_E_KEYS)('解決で拒否する: %s', (_name, key) => {
    expectInvalidDid(() => resolveDidPeer(`did:peer:2.V${ED25519_KEY}.E${key}`));
  });
});
