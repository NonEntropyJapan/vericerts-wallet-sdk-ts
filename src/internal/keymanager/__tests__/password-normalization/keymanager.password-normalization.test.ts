/**
 * パスワードの Unicode 正規化（NFKC）と、正規化導入前に作られたエンベロープとの互換。
 *
 * 見た目が同じ NFC / NFD のパスワードが別鍵になり、正しいパスワードを入力しても復号できず締め出される
 * 問題の回帰テスト。復号は「NFKC 正規化後 → 失敗なら生のパスワード」の順に試すので、正規化導入前に
 * 生のパスワードで暗号化された既存エンベロープも復号できる（互換）。
 */

import { describe, expect, it, setDefaultTimeout } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import { encryptAesGcm } from '../../encryption.js';
import { deriveKey, type KdfParams, serializeKdf } from '../../kdf.js';
import { KeyManager } from '../../keymanager.js';
import { buildEnvelopeAad, packEnvelopeV2 } from '../../vault/envelope-format.js';
import { KDF_TIMEOUT_MS } from '../kdf-policy/kdf-timeout.js';

/** 実 Argon2id を通るため、並列負荷下でも既定 5000ms で落ちないよう猶予を広げる。 */
setDefaultTimeout(KDF_TIMEOUT_MS);

// 最軽量の許可プロファイル（kdf-policy の下限）。
const KDF: KdfParams = { algo: 'argon2id', version: 1, m: 9216, t: 4, p: 1 };
const PLAINTEXT = new TextEncoder().encode('secret mnemonic');

const NFC = 'pässwörd-がぎ-123'.normalize('NFC');
const NFD = NFC.normalize('NFD');
const FULLWIDTH = 'Ｐａｓｓｗｏｒｄ１２３'; // NFKC で ASCII へ変わる

/** 正規化導入前の実装と同じ手順（生のパスワードで鍵導出）で V2 エンベロープを作る。 */
async function legacyEncrypt(password: string): Promise<Uint8Array> {
  const salt = crypto.getRandomValues(new Uint8Array(32));
  const kdfJson = serializeKdf(KDF);
  const key = await deriveKey(KDF, password, salt);
  const { iv, ciphertext } = await encryptAesGcm(key, PLAINTEXT, buildEnvelopeAad(kdfJson));
  return packEnvelopeV2(kdfJson, salt, iv, ciphertext);
}

async function expectDecryptFailed(promise: Promise<unknown>): Promise<void> {
  await expect(promise).rejects.toThrow(new VericertsError(ErrorCodes.DECRYPT_FAILED));
}

describe('KeyManager.encrypt / decrypt のパスワード正規化', () => {
  const km = new KeyManager({ kdf: KDF });

  it('前提: NFC と NFD は別の文字列', () => {
    expect(NFC).not.toBe(NFD);
    expect(NFD.length).toBeGreaterThan(NFC.length);
  });

  it('NFC で暗号化したものを NFD で復号できる', async () => {
    const envelope = await km.encrypt(PLAINTEXT, NFC);

    expect(await km.decrypt(envelope, NFD)).toEqual(PLAINTEXT);
  });

  it('NFD で暗号化したものを NFC で復号できる', async () => {
    const envelope = await km.encrypt(PLAINTEXT, NFD);

    expect(await km.decrypt(envelope, NFC)).toEqual(PLAINTEXT);
  });

  it('全角英数は NFKC で ASCII と同一視される', async () => {
    const envelope = await km.encrypt(PLAINTEXT, FULLWIDTH);

    expect(await km.decrypt(envelope, 'Password123')).toEqual(PLAINTEXT);
  });

  it('正規化しても同じにならない別のパスワードでは復号できない（1050）', async () => {
    const envelope = await km.encrypt(PLAINTEXT, NFC);

    await expectDecryptFailed(km.decrypt(envelope, `${NFC}x`));
  });
});

describe('正規化導入前に作られたエンベロープとの互換（試行順序: 正規化後 → 生）', () => {
  const km = new KeyManager({ kdf: KDF });

  it('生の NFD で暗号化された既存エンベロープを、同じ NFD で復号できる（正規化後は失敗 → 生で成功）', async () => {
    const legacy = await legacyEncrypt(NFD);

    expect(await km.decrypt(legacy, NFD)).toEqual(PLAINTEXT);
  });

  it('生の全角英数で暗号化された既存エンベロープを、同じ全角英数で復号できる', async () => {
    const legacy = await legacyEncrypt(FULLWIDTH);

    expect(await km.decrypt(legacy, FULLWIDTH)).toEqual(PLAINTEXT);
  });

  it('生の NFC（NFKC で不変）で暗号化された既存エンベロープは、NFD の入力でも復号できる', async () => {
    const legacy = await legacyEncrypt(NFC);

    expect(await km.decrypt(legacy, NFD)).toEqual(PLAINTEXT);
    expect(await km.decrypt(legacy, NFC)).toEqual(PLAINTEXT);
  });

  it('ASCII の既存エンベロープは従来どおり復号できる', async () => {
    const legacy = await legacyEncrypt('plain-ascii-password');

    expect(await km.decrypt(legacy, 'plain-ascii-password')).toEqual(PLAINTEXT);
  });

  it('既存エンベロープでも誤パスワードは 1050（フォールバックで誤受理しない）', async () => {
    const legacy = await legacyEncrypt(NFD);

    await expectDecryptFailed(km.decrypt(legacy, `${NFD}x`));
  });

  it('壊れたエンベロープはフォールバックせず 1050 のまま', async () => {
    const envelope = await km.encrypt(PLAINTEXT, NFD);
    envelope[envelope.length - 1] = (envelope[envelope.length - 1] as number) ^ 0xff;

    await expectDecryptFailed(km.decrypt(envelope, NFD));
  });
});
