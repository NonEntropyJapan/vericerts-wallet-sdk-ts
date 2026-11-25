/**
 * KeyManager の encrypt / decrypt（パスワードベース・エンベロープ I/O）の振る舞い検証。
 * 往復一致・誤パスワード・V2 構造・salt/iv 一意性・改ざん検出・未知 version・空平文・各 KDF 往復・
 * 保存 params クロス復号・不正 algo/壊れた JSON の kdfJson 拒否。
 * KDF パラメータポリシー（constructor/decrypt の拒否系）は kdf-policy/keymanager.kdf-policy.test.ts を参照。
 */

import { describe, expect, it, setDefaultTimeout } from 'bun:test';
import type { ErrorCode } from '../../errors.js';
import { VericertsError } from '../../errors.js';
import type { KdfParams } from '../kdf.js';
import { KeyManager } from '../keymanager.js';
import { KDF_TIMEOUT_MS } from './kdf-policy/kdf-timeout.js';

/** 実 Argon2id を通るため、並列負荷下でも既定 5000ms で落ちないよう猶予を広げる。 */
setDefaultTimeout(KDF_TIMEOUT_MS);

const PASSWORD = 'correct horse battery staple';
// 実装側の変更でエンベロープの形式が変わったことを検出できるよう、長さの期待値はここで固定する。
/** ソルトは 256 bit（32 バイト）。 */
const SALT_LENGTH = 32;
const IV_LENGTH = 12;
const TAG_LENGTH = 16;
/** V2 エンベロープのヘッダ長: version(1) + kdfJsonLen(2 BE)。 */
const V2_HEADER_LENGTH = 1 + 2;

/** 最小許可プロファイル argon2id（OWASP 最低コスト最軽量: m=9216 && t=4。許可範囲内で高速化）。 */
const MIN_ARGON2ID: KdfParams = { algo: 'argon2id', version: 1, m: 9216, t: 4, p: 1 };
/** 最小許可プロファイル scrypt（N=2^14, r=8, p=1。許可範囲の最軽量でディスパッチ回帰を守る）。 */
const MIN_SCRYPT: KdfParams = { algo: 'scrypt', version: 1, N: 1 << 14, r: 8, p: 1 };
/** 最小許可プロファイル pbkdf2（iterations=600000。許可下限でディスパッチ回帰を守る）。 */
const MIN_PBKDF2: KdfParams = { algo: 'pbkdf2', version: 1, iterations: 600_000 };

/** VericertsError の code を assert するヘルパ。 */
async function expectRejectCode(promise: Promise<unknown>, code: ErrorCode): Promise<void> {
  try {
    await promise;
    throw new Error('expected rejection');
  } catch (error) {
    expect(error).toBeInstanceOf(VericertsError);
    expect((error as VericertsError).code).toBe(code);
  }
}

/** V2 エンベロープから kdfJsonLen を読み出し、salt の開始オフセットを返す。 */
function saltOffset(envelope: Uint8Array): number {
  const kdfJsonLen = ((envelope[1] ?? 0) << 8) | (envelope[2] ?? 0);
  return V2_HEADER_LENGTH + kdfJsonLen;
}

/**
 * 正常 encrypt 出力の kdfJson 部（生バイト）を差し替えた偽エンベロープを組み立てる。
 * 実 encrypt の salt/iv/ct を再利用し kdfJson と長ヘッダのみ整合差し替えする（モック禁止）。
 */
function withReplacedKdfJsonBytes(envelope: Uint8Array, kdfJson: Uint8Array): Uint8Array {
  const oldLen = ((envelope[1] ?? 0) << 8) | (envelope[2] ?? 0);
  const rest = envelope.subarray(V2_HEADER_LENGTH + oldLen);
  const out = new Uint8Array(V2_HEADER_LENGTH + kdfJson.length + rest.length);
  out[0] = 0x02;
  out[1] = (kdfJson.length >> 8) & 0xff;
  out[2] = kdfJson.length & 0xff;
  out.set(kdfJson, V2_HEADER_LENGTH);
  out.set(rest, V2_HEADER_LENGTH + kdfJson.length);
  return out;
}

/** kdfJson を別の JSON オブジェクトへ差し替えた偽エンベロープを組み立てる。 */
function withReplacedKdfJson(envelope: Uint8Array, replacement: object): Uint8Array {
  return withReplacedKdfJsonBytes(envelope, new TextEncoder().encode(JSON.stringify(replacement)));
}

describe('KeyManager.encrypt / decrypt', () => {
  it('暗号化→復号で平文が一致する（往復・MIN_ARGON2ID）', async () => {
    const km = new KeyManager({ kdf: MIN_ARGON2ID });
    const plaintext = new TextEncoder().encode('secret message');
    const envelope = await km.encrypt(plaintext, PASSWORD);
    const decrypted = await km.decrypt(envelope, PASSWORD);
    expect(Array.from(decrypted)).toEqual(Array.from(plaintext));
  });

  it('誤ったパスワードでは 1050 を投げる', async () => {
    const km = new KeyManager({ kdf: MIN_ARGON2ID });
    const plaintext = new TextEncoder().encode('secret message');
    const envelope = await km.encrypt(plaintext, PASSWORD);
    await expectRejectCode(km.decrypt(envelope, 'wrong password'), '1050');
  });

  it('V2 エンベロープ構造が [0x02 || kdfJsonLen || kdfJson || salt || iv || ct+tag]', async () => {
    const km = new KeyManager({ kdf: MIN_ARGON2ID });
    const plaintext = new TextEncoder().encode('1234567890');
    const envelope = await km.encrypt(plaintext, PASSWORD);
    expect(envelope[0]).toBe(0x02);
    const kdfJsonLen = ((envelope[1] ?? 0) << 8) | (envelope[2] ?? 0);
    // 保存された kdfJson が MIN_ARGON2ID と一致することを確認する。
    const kdfJson = envelope.subarray(V2_HEADER_LENGTH, V2_HEADER_LENGTH + kdfJsonLen);
    expect(JSON.parse(new TextDecoder().decode(kdfJson))).toEqual(MIN_ARGON2ID);
    // 全長 = ヘッダ(3) + kdfJson + salt(32) + iv(12) + 平文 + GCM タグ。
    expect(envelope.length).toBe(
      V2_HEADER_LENGTH + kdfJsonLen + SALT_LENGTH + IV_LENGTH + plaintext.length + TAG_LENGTH,
    );
  });

  it('salt は 256bit = 32 バイトである', async () => {
    const km = new KeyManager({ kdf: MIN_ARGON2ID });
    const plaintext = new TextEncoder().encode('salt length check');
    const envelope = await km.encrypt(plaintext, PASSWORD);
    const kdfJsonLen = ((envelope[1] ?? 0) << 8) | (envelope[2] ?? 0);
    // 実際の salt 長を全長から逆算して検証する（実装が 16 バイトに回帰したら fail させる）。
    const actualSaltLen =
      envelope.length - (V2_HEADER_LENGTH + kdfJsonLen + IV_LENGTH + plaintext.length + TAG_LENGTH);
    expect(actualSaltLen).toBe(32);
  });

  it('同一入力でも salt と iv が毎回異なる', async () => {
    const km = new KeyManager({ kdf: MIN_ARGON2ID });
    const plaintext = new TextEncoder().encode('same input');
    const a = await km.encrypt(plaintext, PASSWORD);
    const b = await km.encrypt(plaintext, PASSWORD);
    const offA = saltOffset(a);
    const offB = saltOffset(b);
    const saltA = a.subarray(offA, offA + SALT_LENGTH);
    const saltB = b.subarray(offB, offB + SALT_LENGTH);
    const ivA = a.subarray(offA + SALT_LENGTH, offA + SALT_LENGTH + IV_LENGTH);
    const ivB = b.subarray(offB + SALT_LENGTH, offB + SALT_LENGTH + IV_LENGTH);
    expect(Array.from(saltA)).not.toEqual(Array.from(saltB));
    expect(Array.from(ivA)).not.toEqual(Array.from(ivB));
  });

  it('暗号文の改ざんは 1050 で検出される', async () => {
    const km = new KeyManager({ kdf: MIN_ARGON2ID });
    const plaintext = new TextEncoder().encode('tamper target');
    const envelope = await km.encrypt(plaintext, PASSWORD);
    // ct の末尾（タグ領域）を 1 ビット反転する。
    const lastIndex = envelope.length - 1;
    envelope[lastIndex] = (envelope[lastIndex] ?? 0) ^ 0x01;
    await expectRejectCode(km.decrypt(envelope, PASSWORD), '1050');
  });

  it('0x02 以外（0x01 含む未知）の version バイトのエンベロープは 1050 を投げる', async () => {
    const km = new KeyManager({ kdf: MIN_ARGON2ID });
    const plaintext = new TextEncoder().encode('versioned');
    const envelope = await km.encrypt(plaintext, PASSWORD);
    envelope[0] = 0x7f;
    await expectRejectCode(km.decrypt(envelope, PASSWORD), '1050');
  });

  it('空の平文も往復できる', async () => {
    const km = new KeyManager({ kdf: MIN_ARGON2ID });
    const plaintext = new Uint8Array(0);
    const envelope = await km.encrypt(plaintext, PASSWORD);
    const decrypted = await km.decrypt(envelope, PASSWORD);
    expect(decrypted.length).toBe(0);
  });

  it('Argon2id でラウンドトリップできる（最小許可パラメータ注入）', async () => {
    const km = new KeyManager({ kdf: MIN_ARGON2ID });
    const plaintext = new TextEncoder().encode('argon2id roundtrip');
    const envelope = await km.encrypt(plaintext, PASSWORD);
    expect(envelope[0]).toBe(0x02);
    const decrypted = await km.decrypt(envelope, PASSWORD);
    expect(Array.from(decrypted)).toEqual(Array.from(plaintext));
  });

  it('復号は保存された KDF パラメータを使う（writer=MIN / reader=既定 のクロス復号）', async () => {
    // MIN で暗号化したエンベロープを既定 params の KeyManager が復号できる＝保存 params を使う証左。
    const writer = new KeyManager({ kdf: MIN_ARGON2ID });
    const plaintext = new TextEncoder().encode('use stored params');
    const envelope = await writer.encrypt(plaintext, PASSWORD);
    const reader = new KeyManager(); // 既定 params(19456,2,1)
    const decrypted = await reader.decrypt(envelope, PASSWORD);
    expect(Array.from(decrypted)).toEqual(Array.from(plaintext));
  });

  it('V2 で不正な algo の kdfJson は 1050 を投げる', async () => {
    const km = new KeyManager({ kdf: MIN_ARGON2ID });
    const plaintext = new TextEncoder().encode('bogus algo');
    const envelope = await km.encrypt(plaintext, PASSWORD);
    const tampered = withReplacedKdfJson(envelope, { algo: 'bogus', version: 1 });
    await expectRejectCode(km.decrypt(tampered, PASSWORD), '1050');
  });

  it('V2 で壊れた JSON の kdfJson は 1050 を投げる', async () => {
    const km = new KeyManager({ kdf: MIN_ARGON2ID });
    const plaintext = new TextEncoder().encode('broken json');
    const envelope = await km.encrypt(plaintext, PASSWORD);
    // 不正 JSON は object でないため生バイト差し替えヘルパで組み立てる。
    const bad = new TextEncoder().encode('{not valid json');
    const tampered = withReplacedKdfJsonBytes(envelope, bad);
    await expectRejectCode(km.decrypt(tampered, PASSWORD), '1050');
  });

  it('scrypt 許可プロファイルでラウンドトリップできる（deriveKey ディスパッチ回帰）', async () => {
    const km = new KeyManager({ kdf: MIN_SCRYPT });
    const plaintext = new TextEncoder().encode('scrypt roundtrip');
    const envelope = await km.encrypt(plaintext, PASSWORD);
    expect(envelope[0]).toBe(0x02);
    const decrypted = await km.decrypt(envelope, PASSWORD);
    expect(Array.from(decrypted)).toEqual(Array.from(plaintext));
  });

  it('pbkdf2 許可プロファイルでラウンドトリップできる（deriveKey ディスパッチ回帰）', async () => {
    const km = new KeyManager({ kdf: MIN_PBKDF2 });
    const plaintext = new TextEncoder().encode('pbkdf2 roundtrip');
    const envelope = await km.encrypt(plaintext, PASSWORD);
    expect(envelope[0]).toBe(0x02);
    const decrypted = await km.decrypt(envelope, PASSWORD);
    expect(Array.from(decrypted)).toEqual(Array.from(plaintext));
  });

  it('既定 Argon2id(19MiB) でラウンドトリップできる（AAD 付き）', async () => {
    const km = new KeyManager(); // 既定 params（argon2id, m=19456）
    const plaintext = new TextEncoder().encode('default argon2id roundtrip');
    const envelope = await km.encrypt(plaintext, PASSWORD);
    expect(envelope[0]).toBe(0x02);
    const decrypted = await km.decrypt(envelope, PASSWORD);
    expect(Array.from(decrypted)).toEqual(Array.from(plaintext));
  }, 30000);
});
