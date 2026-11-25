/**
 * W2W-Transfer 向け ECDH-ES + HKDF-SHA-256 鍵合意（`EncryptionHeader.kdf: "HKDF-SHA-256"` /
 * `recipientKey`）。
 *
 * `recipientKey` 指定時、バックアップ本文の対称鍵は
 * パスフレーズ由来の PBKDF2 ではなく、エクスポート側が都度生成するエフェメラル P-256 鍵と
 * `recipientKey` の ECDH 共有秘密から HKDF-SHA-256 で導出する。対応する秘密鍵の保有者だけが再導出
 * できるため、パスフレーズを知るだけでは復号できない（従来 `recipientKey` は暗号化に
 * 一切影響しないメタデータだった）。
 *
 * `auth/jwe/ecdh.ts` も ECDH-ES 鍵合意だが、あちらは RFC 7518 §4.6.2 Concat KDF を使う OID4VP 応答
 * 暗号化専用であり、仕様が明記する HKDF-SHA-256 を使う本モジュールはバックアップ専用に独立させる。
 *
 * セキュリティ上の注意:
 * - 共有秘密・エフェメラル秘密鍵・受信者秘密鍵を例外メッセージ・context・cause に一切含めない。
 * - エフェメラル鍵ペアはエクスポート 1 回ごとに新規生成する（ECDH-ES の鍵再利用禁止）。
 */

import { p256 } from '@noble/curves/nist.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { type ErrorCode, ErrorCodes, VericertsError } from '../../errors.js';
import { toEpkJwk } from '../../identity/jwt/epk-jwk.js';
import { jwkToUncompressedPublicKey, SUPPORTED_EC_CRV } from '../../identity/jwt/jwk-key.js';
import type { JWK } from '../types.js';

/** EC 座標長（バイト）。導出鍵長（AES-256 = 32 バイト）でもある。 */
const KEY_LENGTH = 32;
/** HKDF-SHA-256 の `info`（コンテキスト分離用の固定値）。 */
const HKDF_INFO = new TextEncoder().encode('vericerts-wallet-backup-v1');

/** ECDH-ES 鍵合意の結果（エクスポート側）。 */
export interface EcdhSenderAgreement {
  /** 導出された 32 バイト鍵（バックアップ本文の対称鍵）。 */
  readonly key: Uint8Array;
  /** エフェメラル公開鍵の JWK（`kdfParams.epk` にそのまま載せる）。 */
  readonly epk: JWK;
}

/** JWK（EC 公開鍵）を SEC1 非圧縮バイト列へ変換する。形式不正は `code` へ正規化する。 */
function toUncompressedPublicKey(jwk: JWK, code: ErrorCode): Uint8Array {
  try {
    return jwkToUncompressedPublicKey(jwk, { expectedCrv: SUPPORTED_EC_CRV, errorCode: code });
  } catch (e) {
    if (e instanceof VericertsError) {
      throw e;
    }
    // JWK 本文を漏らさないため cause は握りつぶす。
    throw new VericertsError(code);
  }
}

/** ECDH 共有秘密（x 座標 32 バイト）を求める。点が曲線上にない等の失敗は `code` へ正規化する。 */
function sharedSecret(privateKey: Uint8Array, publicKey: Uint8Array, code: ErrorCode): Uint8Array {
  try {
    // getSharedSecret は圧縮点（0x02/0x03 プレフィックス + x）を返すため先頭 1 バイトを落とす。
    return p256.getSharedSecret(privateKey, publicKey).slice(1);
  } catch {
    // 例外メッセージが鍵素材を含み得るため cause は渡さない。
    throw new VericertsError(code);
  }
}

/** HKDF-SHA-256 で共有秘密と salt から 32 バイト鍵を導出する。 */
function deriveHkdfKey(secret: Uint8Array, salt: Uint8Array, code: ErrorCode): Uint8Array {
  try {
    return hkdf(sha256, secret, salt, HKDF_INFO, KEY_LENGTH);
  } catch {
    throw new VericertsError(code);
  }
}

/**
 * エクスポート側: 新規エフェメラル鍵ペアで `recipientKey` と ECDH-ES 鍵合意し、HKDF-SHA-256 で
 * 32 バイト鍵を導出する。
 *
 * @param recipientKey 受信者の EC 公開鍵 JWK（`crv=P-256`）。
 * @param salt HKDF の salt（`kdfParams.salt` と同じ値を共有する）。
 * @returns 導出鍵と、`kdfParams.epk` に載せるエフェメラル公開鍵 JWK。
 * @throws `recipientKey` の形式が不正、または鍵合意・導出に失敗した場合
 *   （VericertsError、code `ENCRYPT_FAILED`）。
 */
export function deriveEcdhKeyForRecipient(
  recipientKey: JWK,
  salt: Uint8Array,
): EcdhSenderAgreement {
  const recipientPublic = toUncompressedPublicKey(recipientKey, ErrorCodes.ENCRYPT_FAILED);

  let ephemeralSecret: Uint8Array;
  let ephemeralPublic: Uint8Array;
  try {
    ephemeralSecret = p256.utils.randomSecretKey();
    ephemeralPublic = p256.getPublicKey(ephemeralSecret, false);
  } catch {
    throw new VericertsError(ErrorCodes.ENCRYPT_FAILED);
  }

  const secret = sharedSecret(ephemeralSecret, recipientPublic, ErrorCodes.ENCRYPT_FAILED);
  const key = deriveHkdfKey(secret, salt, ErrorCodes.ENCRYPT_FAILED);
  return { key, epk: toEpkJwk(ephemeralPublic) };
}

/**
 * インポート側: `recipientKey` に対応する秘密鍵と `kdfParams.epk`（エクスポート側のエフェメラル
 * 公開鍵）から同じ ECDH 共有秘密を再導出し、HKDF-SHA-256 で同じ 32 バイト鍵を復元する。
 *
 * @param recipientPrivateKey `recipientKey` に対応する P-256 秘密鍵（32 バイト raw scalar）。
 * @param epk エクスポート側のエフェメラル公開鍵 JWK（`kdfParams.epk`）。
 * @param salt HKDF の salt（`kdfParams.salt`）。
 * @returns 導出鍵（バックアップ本文の復号に使う 32 バイト）。
 * @throws `epk` の形式が不正、または鍵合意・導出に失敗した場合（VericertsError、code
 *   `DECRYPT_FAILED`）。公開 API へはそのまま出さず、`backup-container-key.ts` が 4033
 *   （壊れたコンテナ）へ正規化する。
 */
export function deriveEcdhKeyFromEphemeral(
  recipientPrivateKey: Uint8Array,
  epk: JWK,
  salt: Uint8Array,
): Uint8Array {
  const ephemeralPublic = toUncompressedPublicKey(epk, ErrorCodes.DECRYPT_FAILED);
  const secret = sharedSecret(recipientPrivateKey, ephemeralPublic, ErrorCodes.DECRYPT_FAILED);
  return deriveHkdfKey(secret, salt, ErrorCodes.DECRYPT_FAILED);
}
