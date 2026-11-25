/**
 * DIDComm v2 JWE の低レベル暗号プリミティブ（ECDH-ES 鍵合意 + Concat KDF + AES-KW + AES-GCM）。
 *
 * `jwe.ts`（Compact Serialization の組み立て・分解）から分離する（linterly の 1 ファイル
 * 300 行上限。`auth/jwe/` の `jwe.ts` / `ecdh.ts` 分割と同じ理由）。
 *
 * セキュリティ上の注意:
 * - 例外メッセージ・`context` に鍵素材・平文を含めない。
 */

import { p256 } from '@noble/curves/nist.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { concatBytes, toBufferSource } from '../asset/bytes.js';
import type { ErrorCode } from '../errors.js';
import { ErrorCodes, VericertsError } from '../errors.js';
import type { PublicKeyJwk } from '../identity/did.js';
import { jwkToUncompressedPublicKey } from '../identity/jwt/jwk-key.js';

/** EC 座標長（P-256、32 バイト）。CEK / KEK 長でもある。 */
export const KEY_LENGTH = 32;
/** Concat KDF が導出する鍵長（ビット）。 */
export const KEYDATALEN_BITS = 256;
/** GCM の IV 長（バイト）。 */
export const IV_LENGTH = 12;
/** GCM 認証タグ長（バイト）。 */
export const TAG_LENGTH = 16;
/** GCM 認証タグ長（ビット）。 */
export const TAG_LENGTH_BITS = 128;

function uint32BE(value: number): Uint8Array {
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, value, false);
  return out;
}

function lengthPrefixed(bytes: Uint8Array): Uint8Array {
  return concatBytes(uint32BE(bytes.length), bytes);
}

/** Concat KDF（NIST SP 800-56A §5.8.1 / RFC 7518 §4.6.2）。`keydatalen` が SHA-256 出力長と一致するため 1 ラウンドで足りる。 */
export function concatKdf(sharedSecret: Uint8Array, algorithmId: string): Uint8Array {
  const empty = new Uint8Array(0);
  const input = concatBytes(
    uint32BE(1),
    sharedSecret,
    lengthPrefixed(new TextEncoder().encode(algorithmId)),
    lengthPrefixed(empty),
    lengthPrefixed(empty),
    uint32BE(KEYDATALEN_BITS),
  );
  return sha256(input);
}

/** JWK（P-256）を SEC1 非圧縮バイト列へ変換する。失敗時のコードは呼び出し側の面（送信/受信）で切り替える。 */
export function publicKeyBytesFromJwk(jwk: PublicKeyJwk, failureCode: ErrorCode): Uint8Array {
  try {
    return jwkToUncompressedPublicKey(jwk, { expectedCrv: 'P-256', errorCode: failureCode });
  } catch (error) {
    if (error instanceof VericertsError) {
      throw error;
    }
    throw new VericertsError(failureCode);
  }
}

/** ECDH 共有秘密 `Z`（x 座標 32 バイト）を求める。失敗時のコードは呼び出し側の面で切り替える。 */
export function deriveSharedSecret(
  privateKey: Uint8Array,
  publicKey: Uint8Array,
  failureCode: ErrorCode,
): Uint8Array {
  try {
    return p256.getSharedSecret(privateKey, publicKey).slice(1);
  } catch {
    throw new VericertsError(failureCode);
  }
}

export async function wrapCek(kek: Uint8Array, cek: Uint8Array): Promise<Uint8Array> {
  try {
    const kekKey = await crypto.subtle.importKey(
      'raw',
      toBufferSource(kek),
      { name: 'AES-KW' },
      false,
      ['wrapKey'],
    );
    const cekKey = await crypto.subtle.importKey(
      'raw',
      toBufferSource(cek),
      { name: 'AES-GCM' },
      true,
      ['encrypt'],
    );
    return new Uint8Array(await crypto.subtle.wrapKey('raw', cekKey, kekKey, 'AES-KW'));
  } catch {
    throw new VericertsError(ErrorCodes.DIDCOMM_PACK_FAILED);
  }
}

/** ラップされた CEK を KEK でアンラップする。失敗（鍵不一致含む）は `DIDCOMM_UNPACK_FAILED`。 */
export async function unwrapCek(kek: Uint8Array, wrapped: Uint8Array): Promise<Uint8Array> {
  try {
    const kekKey = await crypto.subtle.importKey(
      'raw',
      toBufferSource(kek),
      { name: 'AES-KW' },
      false,
      ['unwrapKey'],
    );
    const cekKey = await crypto.subtle.unwrapKey(
      'raw',
      toBufferSource(wrapped),
      kekKey,
      'AES-KW',
      { name: 'AES-GCM' },
      true,
      ['decrypt'],
    );
    return new Uint8Array(await crypto.subtle.exportKey('raw', cekKey));
  } catch {
    // 受信者秘密鍵が対応する keyAgreement 鍵でない場合を含む（鍵素材は含めない）。
    throw new VericertsError(ErrorCodes.DIDCOMM_UNPACK_FAILED);
  }
}

export async function encryptContent(
  cek: Uint8Array,
  iv: Uint8Array,
  plaintext: Uint8Array,
  aad: Uint8Array,
): Promise<{ readonly ciphertext: Uint8Array; readonly tag: Uint8Array }> {
  try {
    const key = await crypto.subtle.importKey(
      'raw',
      toBufferSource(cek),
      { name: 'AES-GCM' },
      false,
      ['encrypt'],
    );
    const combined = new Uint8Array(
      await crypto.subtle.encrypt(
        {
          name: 'AES-GCM',
          iv: toBufferSource(iv),
          tagLength: TAG_LENGTH_BITS,
          additionalData: toBufferSource(aad),
        },
        key,
        toBufferSource(plaintext),
      ),
    );
    return {
      ciphertext: combined.slice(0, combined.length - TAG_LENGTH),
      tag: combined.slice(combined.length - TAG_LENGTH),
    };
  } catch {
    throw new VericertsError(ErrorCodes.DIDCOMM_PACK_FAILED);
  }
}

export async function decryptContent(
  cek: Uint8Array,
  iv: Uint8Array,
  ciphertext: Uint8Array,
  tag: Uint8Array,
  aad: Uint8Array,
): Promise<Uint8Array> {
  try {
    const key = await crypto.subtle.importKey(
      'raw',
      toBufferSource(cek),
      { name: 'AES-GCM' },
      false,
      ['decrypt'],
    );
    const combined = concatBytes(ciphertext, tag);
    return new Uint8Array(
      await crypto.subtle.decrypt(
        {
          name: 'AES-GCM',
          iv: toBufferSource(iv),
          tagLength: TAG_LENGTH_BITS,
          additionalData: toBufferSource(aad),
        },
        key,
        toBufferSource(combined),
      ),
    );
  } catch {
    // GCM 認証タグ不一致（誤った CEK・改ざん）は復号失敗として扱う。
    throw new VericertsError(ErrorCodes.DIDCOMM_UNPACK_FAILED);
  }
}
