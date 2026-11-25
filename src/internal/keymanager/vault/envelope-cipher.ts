/**
 * パスワードベースの AES-256-GCM 暗号化エンベロープ（V2）の pack / unpack 純粋関数。
 *
 * KeyManager facade（keymanager.ts）から暗号化・復号ロジックを分離し、行数上限（CI 規約:
 * 1 ファイル 300 行以下）に対応する。KeyManager は本モジュールへ委譲する薄い facade に徹する。
 *
 * V2 エンベロープ構造:
 * `[version(0x02)] || [kdfJsonLen(2 BE)] || [kdfJson] || [salt(32)] || [iv(12)] || [ciphertext+tag]`。
 *
 * セキュリティ上の注意:
 * - 平文 / password / 導出鍵を例外 message / context / cause に一切含めない。
 * - 委譲先（encryption.ts / kdf.ts）が秘密を含まない `VericertsError` に正規化済みのため、そのまま伝播する。
 */

import { ErrorCodes, VericertsError } from '../../errors.js';
import { decryptAesGcm, encryptAesGcm } from '../encryption.js';
import { deriveKey as deriveKeyFromPassword, type KdfParams, serializeKdf } from '../kdf.js';
import { buildEnvelopeAad, packEnvelopeV2, unpackEnvelopeV2 } from './envelope-format.js';
import { isNonEmptyPassword } from './password-policy.js';

/**
 * KDF へ渡すパスワードを Unicode 正規化する（NFKC、RFC 8265 / OWASP 推奨）。
 *
 * 正規化しないと、見た目が同じ NFC と NFD（IME / OS / 貼り付け元で混在する日本語・アクセント付き文字）が
 * 別鍵になり、正しいパスワードを入力しても復号できず締め出される（ニーモニックの `@scure/bip39` は NFKD を
 * 行うのに対し、パスワード経路だけ生の UTF-8 を渡していた）。
 */
function normalizePassword(password: string): string {
  return password.normalize('NFKC');
}

/** 暗号化エンベロープの salt 長（32 バイト）。 */
const SALT_LENGTH = 32;
/** V2 エンベロープのバージョンバイト（新既定）。KDF パラメータをエンベロープに内包する。 */
const ENVELOPE_VERSION_V2 = 0x02;

/**
 * パスワード由来の鍵で平文を AES-256-GCM 暗号化し、自己完結な V2 エンベロープを返す。
 *
 * 鍵導出は `kdf`（既定 argon2id）で行い、復号に必要な KDF パラメータをエンベロープに内包する。
 *
 * @param kdf 鍵導出パラメータ（正規化済みを想定）。
 * @param plaintext 暗号化対象の平文（0 バイト以上）。
 * @param password 暗号化パスワード。
 * @returns 復号に必要な情報（KDF パラメータ含む）を内包した V2 エンベロープ。
 * @throws 鍵導出・暗号化に失敗した場合、パスワードが空文字・非文字列の場合（VericertsError、code `1051`）。
 */
export async function encryptEnvelope(
  kdf: KdfParams,
  plaintext: Uint8Array,
  password: string,
): Promise<Uint8Array> {
  // 空文字は KDF 入力として成立し実質無鍵になる。非文字列は KDF 側の暗黙変換に任せない。
  if (!isNonEmptyPassword(password)) {
    throw new VericertsError(ErrorCodes.ENCRYPT_FAILED);
  }
  const salt = crypto.getRandomValues(new Uint8Array(SALT_LENGTH));
  // kdfJson と AAD（先頭メタ）を鍵導出前に確定し、エンベロープと AES-GCM の AAD を同一バイト列にする。
  const kdfJson = serializeKdf(kdf);
  const aad = buildEnvelopeAad(kdfJson);
  const aesKey = await deriveKeyFromPassword(kdf, normalizePassword(password), salt);
  try {
    const { iv, ciphertext } = await encryptAesGcm(aesKey, plaintext, aad);
    return packEnvelopeV2(kdfJson, salt, iv, ciphertext);
  } finally {
    // 導出 AES 鍵をメモリから消去する。
    aesKey.fill(0);
  }
}

/**
 * `encryptEnvelope` が生成したエンベロープをパスワードで復号する。
 *
 * 対応は V2（0x02）のみ。エンベロープ内の KDF パラメータで鍵導出する。
 *
 * **互換: 試行順序は「NFKC 正規化後 → 失敗したら生のパスワード」の 2 段**。正規化の導入前に
 * 暗号化されたエンベロープは生のパスワードで鍵導出されており、正規化後だけで復号すると、NFKC で
 * 変化する文字（NFD・全角英数など）を含むパスワードの既存エンベロープが復号不能になる。2 段目は正規化で
 * 文字列が変わるパスワードに限る（ASCII など変化しない場合は 1 回だけ導出する）。2 段目は認証失敗
 * （1050）のときだけ試し、KDF 失敗（1051）などは握り潰さない。
 *
 * @param ciphertext `encryptEnvelope` の出力エンベロープ（V2）。
 * @param password 暗号化時と同一のパスワード。
 * @returns 復号された平文。
 * @throws エンベロープ形式不正・未知 version・KDF パラメータ前提違反（範囲外・巨大値・不正キー）・
 *         誤パスワード・改ざん・AAD 不一致の場合（VericertsError、code `1050`）。
 */
export async function decryptEnvelope(
  ciphertext: Uint8Array,
  password: string,
): Promise<Uint8Array> {
  // unpackEnvelope 内で ct 長ガード → parseKdf（validateKdfParams 済み）を経るため、
  // 不正・巨大パラメータは鍵導出前に 1050 で弾かれる。
  const { kdf, salt, iv, ct, aad } = unpackEnvelope(ciphertext);
  const normalized = normalizePassword(password);
  try {
    return await decryptWith(kdf, normalized, salt, iv, ct, aad);
  } catch (e) {
    if (
      normalized === password ||
      !(e instanceof VericertsError) ||
      e.code !== ErrorCodes.DECRYPT_FAILED
    ) {
      throw e;
    }
    // 正規化導入前に作られたエンベロープ（生のパスワードで導出）。
    return decryptWith(kdf, password, salt, iv, ct, aad);
  }
}

/** 指定パスワードで鍵導出して復号する（導出鍵は必ず消去する）。 */
async function decryptWith(
  kdf: KdfParams,
  password: string,
  salt: Uint8Array,
  iv: Uint8Array,
  ct: Uint8Array,
  aad: Uint8Array,
): Promise<Uint8Array> {
  const aesKey = await deriveKeyFromPassword(kdf, password, salt);
  try {
    // 誤パスワード・改ざん・AAD 不一致は decryptAesGcm 内で 1050 に正規化される。
    return await decryptAesGcm(aesKey, iv, ct, aad);
  } finally {
    aesKey.fill(0);
  }
}

/**
 * エンベロープを先頭バージョンバイトで分岐し、KDF パラメータと salt / iv / ct へ分解する。
 *
 * @throws 未知 version・長さ不足・KDF 不正の場合（VericertsError、code `1050`）。
 */
function unpackEnvelope(envelope: Uint8Array): {
  kdf: KdfParams;
  salt: Uint8Array;
  iv: Uint8Array;
  ct: Uint8Array;
  aad: Uint8Array;
} {
  const version = envelope[0];
  if (version === ENVELOPE_VERSION_V2) {
    return unpackEnvelopeV2(envelope);
  }
  throw new VericertsError(ErrorCodes.DECRYPT_FAILED);
}
