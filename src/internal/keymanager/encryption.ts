/**
 * AES-256-GCM 対称暗号化・復号の純粋関数モジュール。
 *
 * VC / 秘密鍵などの機密データをローカル保管する際の対称暗号プリミティブを提供する。
 * Web Crypto API（`globalThis.crypto.subtle` / `crypto.getRandomValues`）をバックエンドに
 * 用い、bun / Node 20+ / ブラウザのいずれでもグローバルに利用できるため import は不要。
 *
 * スコープ境界:
 * - 本モジュールは「生 256bit 鍵」を受領する前提の対称暗号プリミティブのみを担当する。
 *   パスワード等からの鍵導出（KDF: PBKDF2 / Argon2 等）は本モジュールの責務外。
 * - IV（96bit）は暗号化のたびに一意なランダム値を生成する。同一鍵で IV を再利用すると
 *   GCM の機密性・完全性が破綻するため、呼び出し側が IV を指定する API は公開 re-export しない。
 *
 * セキュリティ上の注意:
 * - 鍵 / 平文 / IV / 暗号文などの機密・入力データは、例外メッセージ・`context`・`cause` に
 *   一切含めない。
 * - エラーは `VericertsError` に正規化する。Web Crypto 由来の例外は
 *   メッセージに情報が含まれ得るため、`cause` を渡さず握りつぶす（hd.ts / signer.ts と同様）。
 * - 鍵は `importKey` 時に `extractable: false` とし、鍵素材の再エクスポートを防ぐ。
 */

import { toBufferSource } from '../asset/bytes.js';
import { ErrorCodes, VericertsError } from '../errors.js';

/** AES-256-GCM の鍵長（バイト）。256bit = 32 バイト固定。 */
const KEY_LENGTH = 32;
/** GCM の IV（nonce）長（バイト）。GCM 推奨の 96bit = 12 バイト。 */
const IV_LENGTH = 12;
/** GCM 認証タグ長（ビット）。Web Crypto 既定と一致させ意図を明示する（128bit = 16 バイト）。 */
const TAG_LENGTH_BITS = 128;

/**
 * AES-256-GCM の暗号化結果。
 *
 * `ciphertext` は Web Crypto の出力に従い「暗号文 || 16 バイト GCM タグ」を連結した形式。
 * 復号には `iv` と `ciphertext`（と暗号化時と同一の AAD）が必要。
 */
export interface AesGcmCiphertext {
  /** ランダムに生成された IV（12 バイト）。 */
  readonly iv: Uint8Array;
  /** 暗号文 || 16 バイト GCM 認証タグ。 */
  readonly ciphertext: Uint8Array;
}

/**
 * 生 256bit 鍵を Web Crypto の AES-GCM `CryptoKey` へ取り込む。
 *
 * `extractable: false` とし、鍵素材の再エクスポートを禁止する。
 *
 * @param key 生の鍵（32 バイト）。
 * @returns AES-GCM 用の `CryptoKey`。
 * @throws 鍵長が 32 バイトでない / importKey が失敗した場合（VericertsError、code `1051`）。
 */
async function importAesKey(key: Uint8Array): Promise<CryptoKey> {
  if (key.length !== KEY_LENGTH) {
    // 鍵素材はメッセージに含めない。
    throw new VericertsError(ErrorCodes.ENCRYPT_FAILED);
  }
  try {
    return await crypto.subtle.importKey('raw', toBufferSource(key), { name: 'AES-GCM' }, false, [
      'encrypt',
      'decrypt',
    ]);
  } catch {
    // Web Crypto 由来の例外は cause を渡さず握りつぶす。
    throw new VericertsError(ErrorCodes.ENCRYPT_FAILED);
  }
}

/**
 * 呼び出し側が指定した IV で AES-256-GCM 暗号化を行う（CAVP テスト専用）。
 *
 * **警告**: 既知ベクター検証など決定論的なテスト用途のみを想定する。同一鍵での IV 再利用は
 * GCM の安全性を破壊するため、本番コードは必ず {@link encryptAesGcm}（IV をランダム生成）を使う。
 * このため本関数は SDK の公開エントリポイント（index.ts）から re-export しない。
 *
 * @param key 生の鍵（32 バイト）。
 * @param iv IV（12 バイト）。
 * @param plaintext 暗号化対象の平文（0 バイト以上）。
 * @param aad 付加認証データ（任意）。指定時は復号時も同一値が必要。
 * @returns `iv` と「暗号文 || 16 バイトタグ」。
 * @throws 鍵長 / IV 長不正・Web Crypto エラーの場合（VericertsError、code `1051`）。
 */
export async function encryptAesGcmWithIv(
  key: Uint8Array,
  iv: Uint8Array,
  plaintext: Uint8Array,
  aad?: Uint8Array,
): Promise<AesGcmCiphertext> {
  if (iv.length !== IV_LENGTH) {
    throw new VericertsError(ErrorCodes.ENCRYPT_FAILED);
  }
  // 鍵長検証（≠32B→1051）・importKey 失敗（→1051）は importAesKey に集約する。
  const cryptoKey = await importAesKey(key);
  // AAD がある場合のみ additionalData を付与する（復号時と一致させる必要がある）。
  const params: AesGcmParams =
    aad !== undefined
      ? {
          name: 'AES-GCM',
          iv: toBufferSource(iv),
          tagLength: TAG_LENGTH_BITS,
          additionalData: toBufferSource(aad),
        }
      : { name: 'AES-GCM', iv: toBufferSource(iv), tagLength: TAG_LENGTH_BITS };
  try {
    const buf = await crypto.subtle.encrypt(params, cryptoKey, toBufferSource(plaintext));
    return { iv, ciphertext: new Uint8Array(buf) };
  } catch {
    // Web Crypto 由来の例外は cause を渡さず握りつぶす。
    throw new VericertsError(ErrorCodes.ENCRYPT_FAILED);
  }
}

/**
 * AES-256-GCM で暗号化する。IV（12 バイト）は暗号化のたびにランダム生成する。
 *
 * @param key 生の鍵（32 バイト）。
 * @param plaintext 暗号化対象の平文（0 バイト以上）。
 * @param aad 付加認証データ（任意）。指定時は復号時も同一値が必要。
 * @returns ランダムな `iv` と「暗号文 || 16 バイトタグ」。
 * @throws 鍵長不正・Web Crypto エラーの場合（VericertsError、code `1051`）。
 */
export function encryptAesGcm(
  key: Uint8Array,
  plaintext: Uint8Array,
  aad?: Uint8Array,
): Promise<AesGcmCiphertext> {
  // IV は暗号化ごとに一意なランダム値とする（GCM の安全性要件）。
  const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));
  return encryptAesGcmWithIv(key, iv, plaintext, aad);
}

/**
 * AES-256-GCM で復号し、GCM 認証タグを検証する。
 *
 * タグ不一致・改ざん・AAD 不一致は復号失敗（1050）に正規化する。鍵長 / IV 長などの
 * 前提違反（呼び出し側のパラメータ誤り）は暗号化失敗側（1051）として区別する。
 *
 * @param key 生の鍵（32 バイト）。
 * @param iv 暗号化時に用いた IV（12 バイト）。
 * @param ciphertext 暗号文 || 16 バイト GCM タグ。
 * @param aad 暗号化時と同一の付加認証データ（任意）。
 * @returns 復号された平文。
 * @throws 鍵長 / IV 長不正の場合（VericertsError、code `1051`）、
 *         タグ検証失敗・改ざん・AAD 不一致の場合（VericertsError、code `1050`）。
 */
export async function decryptAesGcm(
  key: Uint8Array,
  iv: Uint8Array,
  ciphertext: Uint8Array,
  aad?: Uint8Array,
): Promise<Uint8Array> {
  if (iv.length !== IV_LENGTH) {
    // パラメータ前提違反は復号タグ失敗（1050）とは区別し 1051 とする。
    throw new VericertsError(ErrorCodes.ENCRYPT_FAILED);
  }
  // 鍵長検証（≠32B→1051）・importKey 失敗（→1051）は importAesKey に集約する。
  const cryptoKey = await importAesKey(key);
  const params: AesGcmParams =
    aad !== undefined
      ? {
          name: 'AES-GCM',
          iv: toBufferSource(iv),
          tagLength: TAG_LENGTH_BITS,
          additionalData: toBufferSource(aad),
        }
      : { name: 'AES-GCM', iv: toBufferSource(iv), tagLength: TAG_LENGTH_BITS };
  try {
    const buf = await crypto.subtle.decrypt(params, cryptoKey, toBufferSource(ciphertext));
    return new Uint8Array(buf);
  } catch (e) {
    // 自前で投げた前提違反（1051）はそのまま再 throw し、1050 に混ぜない。
    if (e instanceof VericertsError) {
      throw e;
    }
    // タグ不一致 / 改ざん / AAD 不一致は OperationError として届く。cause は渡さない。
    throw new VericertsError(ErrorCodes.DECRYPT_FAILED);
  }
}
