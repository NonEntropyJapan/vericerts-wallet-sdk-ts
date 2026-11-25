/**
 * RP 別 Pseudonym 鍵の HKDF 派生。
 *
 * `HKDF-SHA256(ikm=master_seed, salt=canonicalize(rp_id), info="eudi-pseudonym-v1")` で
 * P-256 秘密鍵を決定的に派生する。同一 `rpIdentifier` + 同一 `masterSeed` からは常に同一鍵を
 * 得（同一 RP 内継続性）、異なる RP には HKDF の一方向性により相関不能な別鍵を得る。
 *
 * セキュリティ上の注意:
 * - 派生秘密鍵・master_seed・HKDF 出力を例外 message / context / cause に一切含めない。
 * - `@noble` / keymanager 由来の例外は cause を渡さず `VericertsError` に正規化する。
 */

import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { base64urlnopad } from '@scure/base';
import { ErrorCodes, VericertsError } from '../../errors.js';
import { getP256PublicKey } from '../../keymanager/signer.js';
import { canonicalizeRpIdentifier } from '../../rp-identifier.js';
import { PSEUDONYM_HKDF_INFO, PSEUDONYM_SUBJECT_PREFIX, type PseudonymKey } from './types.js';

/** P-256 秘密鍵のバイト長。HKDF の出力長に用いる。 */
const P256_PRIVATE_KEY_LENGTH = 32;

/**
 * RP 識別子を派生 salt 用に正規化する。
 *
 * 実装は横断ヘルパー `internal/rp-identifier.ts` の `canonicalizeRpIdentifier` に委譲する（
 * `persona`（Foundation 層）からも同じ正規化規則で参照する必要が生じたため切り出した。挙動は変更
 * していない）。本モジュールからも従来どおり import できるよう re-export する。
 */
export { canonicalizeRpIdentifier };

/**
 * 派生済み公開鍵から Pseudonym subject 識別子を計算する。
 *
 * `urn:pseudonym:<base64url(sha256(publicKey))>` を返す。RP 側はこの `sub` をキーにユーザーを
 * 特定するため、同一鍵からは常に同一 subject が得られる（決定的）。
 *
 * @param publicKey P-256 圧縮公開鍵（33 バイト）。
 * @returns Pseudonym subject 識別子。
 */
export function computePseudonymSubject(publicKey: Uint8Array): string {
  const digest = sha256(publicKey);
  return `${PSEUDONYM_SUBJECT_PREFIX}${base64urlnopad.encode(digest)}`;
}

/**
 * RP 別 Pseudonym 鍵を HKDF-SHA256 で派生する。
 *
 * `salt = canonicalize(rpIdentifier)`（UTF-8）、`ikm = masterSeed`、`info = "eudi-pseudonym-v1"` で
 * 32 バイトを導出し P-256 秘密鍵とする。HKDF 出力が P-256 の有効な scalar 範囲外の場合は
 * 派生失敗として扱う（実用上ほぼ発生しないが、決定性を損なわないため再派生せず失敗を返す）。
 *
 * @param rpIdentifier RP のクライアント識別子（正規化前）。
 * @param masterSeed マスター種（WSCD 管理の `pseudonym_master_seed`）。
 * @returns 派生した Pseudonym 鍵ペアと subject 識別子。
 * @throws RP 識別子不正の場合（code `10201`）、マスター種が空・全ゼロ、または HKDF / 鍵派生失敗の場合（code `10202`）。
 */
export function derivePseudonym(rpIdentifier: string, masterSeed: Uint8Array): PseudonymKey {
  const rpId = canonicalizeRpIdentifier(rpIdentifier);
  // 空・全ゼロのマスター種は拒否する。全ゼロは消去済み配列の取り違えで現れ、公開値のため
  // 全利用者・全 RP で同一の Pseudonym になりオフライン計算もできる。静かに導出せず fail-closed にする。
  if (
    !(masterSeed instanceof Uint8Array) ||
    masterSeed.length === 0 ||
    masterSeed.every((b) => b === 0)
  ) {
    throw new VericertsError(ErrorCodes.KEY_DERIVATION_FAILED);
  }
  let privateKey: Uint8Array;
  try {
    const salt = new TextEncoder().encode(rpId);
    const info = new TextEncoder().encode(PSEUDONYM_HKDF_INFO);
    privateKey = hkdf(sha256, masterSeed, salt, info, P256_PRIVATE_KEY_LENGTH);
  } catch {
    // HKDF 由来の例外は秘密（seed / 出力）を含み得るため cause を渡さず正規化する。
    throw new VericertsError(ErrorCodes.KEY_DERIVATION_FAILED);
  }
  let publicKey: Uint8Array;
  try {
    publicKey = getP256PublicKey(privateKey, true);
  } catch {
    // HKDF 出力が P-256 の有効 scalar 範囲外（getP256PublicKey が INVALID_PRIVATE_KEY を送出）。
    // 秘密を含み得るため cause は渡さず、派生失敗（10202）へ正規化する。
    throw new VericertsError(ErrorCodes.KEY_DERIVATION_FAILED);
  }
  return {
    rpId,
    privateKey,
    publicKey,
    subject: computePseudonymSubject(publicKey),
  };
}
