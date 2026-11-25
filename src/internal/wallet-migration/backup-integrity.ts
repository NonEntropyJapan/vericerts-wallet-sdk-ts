/**
 * バックアップコンテナの完全性証明（`IntegrityProof`。ES256 detached 署名）。
 *
 * 署名対象の直列化はエクスポート側
 * （署名生成）とインポート側（検証）で完全に一致する必要があるため、`backupDigest` を単一
 * ソースにして `backup.ts` から切り出している。
 *
 * セキュリティ上の注意:
 * - 自己署名を信頼しないように、検証鍵はコンテナの外から受け取る。
 *   本ファイルは呼び出し側が帯域外で調達した `signerPublicKeyJwk` のみを受け取る。
 */

import { sha256 } from '@noble/hashes/sha2.js';
import { base64urlnopad } from '@scure/base';
import type { PublicKeyJwk } from '../identity/did.js';
import { jwkToUncompressedPublicKey } from '../identity/jwt/jwk-key.js';
import { verifyP256 } from '../keymanager/signer.js';
import { ownProperty } from '../prototype-safety/own-property.js';
import { BACKUP_SIGNATURE_ALG, W2W_SIGNER_JWK_OPTIONS, type WalletBackup } from './types.js';

const textEncoder = new TextEncoder();

/**
 * 署名対象（`integrity` を除いたコンテナ）を決定論的に直列化して SHA-256 digest を返す。
 *
 * JSON のキー順は `backup.ts` が固定順で構築するため、`JSON.stringify` の列挙順で安定する。
 *
 * @param backup `integrity` を除いた WalletBackup。
 * @returns 署名対象の SHA-256 digest（32 バイト）。
 */
export function backupDigest(backup: Omit<WalletBackup, 'integrity'>): Uint8Array {
  return sha256(textEncoder.encode(JSON.stringify(backup)));
}

/**
 * バックアップの完全性証明（ES256 detached 署名）を検証する。
 *
 * @param backup 検証対象のバックアップ。
 * @param signerPublicKeyJwk 署名者の EC 公開鍵 JWK（`crv: 'P-256'`）。呼び出し側が帯域外で調達する。
 * @returns 署名が有効なら `true`。
 */
export function verifyIntegrity(backup: WalletBackup, signerPublicKeyJwk: PublicKeyJwk): boolean {
  // `integrity` / `alg` / `signature` は own 限定で読む。手組みの backup が省略したメンバを
  // `Object.prototype` の汚染値で補って完全性の判定に進まないようにする。
  const integrity = ownProperty<WalletBackup['integrity']>(backup, 'integrity');
  if (typeof integrity !== 'object' || integrity === null) {
    return false;
  }
  if (ownProperty<unknown>(integrity, 'alg') !== BACKUP_SIGNATURE_ALG) {
    return false;
  }
  let signature: Uint8Array;
  try {
    signature = base64urlnopad.decode(ownProperty<string>(integrity, 'signature') as string);
  } catch {
    return false;
  }
  const { integrity: _integrity, ...unsigned } = backup;
  const publicKey = jwkToUncompressedPublicKey(signerPublicKeyJwk, W2W_SIGNER_JWK_OPTIONS);
  // JWS ではないため ES256 の high-S 受理の対象外。W2W の署名契約は low-S 固定
  // のため `allowHighS: false` を明示する。
  return verifyP256(backupDigest(unsigned), signature, publicKey, { allowHighS: false });
}
