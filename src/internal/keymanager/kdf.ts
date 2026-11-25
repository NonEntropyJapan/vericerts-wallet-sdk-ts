/**
 * KDF（鍵導出関数）の型・既定値・導出ディスパッチ・直列化・復元を集約するモジュール。
 *
 * 本モジュールは KeyManager のストレージ暗号化鍵（K4）に関する KDF 周りの責務を keymanager.ts から
 * 分離し、後者を薄い facade に保つために存在する。暗号化エンベロープの byte 列 pack/unpack（本モジュール
 * の `parseKdf` を利用する）は行数上限（CI 規約: 1 ファイル 300 行以下）対応で `vault/envelope-format.ts`
 * へ分離した。相互参照になるため本モジュールからの再エクスポートはせず、呼び出し側が両モジュールを
 * それぞれ import する。
 *
 * 仕様（SSOT）:
 * - KDF パラメータは Vault の `kdf` フィールドで使われ、`algo` で判別する。
 * - K4 既定は argon2id。salt 長は 32 バイト（256bit）。
 *
 * セキュリティ上の注意:
 * - password / salt / 導出鍵 / 平文などの秘密は、例外 message / context / cause に一切含めない。
 * - @noble / Web Crypto 由来の例外は、メッセージに秘密が含まれ得るため `cause` を渡さず
 *   `VericertsError` に正規化する。
 */

import { argon2idAsync } from '@noble/hashes/argon2.js';
import { scryptAsync } from '@noble/hashes/scrypt.js';
import { ErrorCodes, VericertsError } from '../errors.js';
import { parseJsonWithoutPrototype } from '../prototype-safety/parse-json.js';
import {
  ALLOWED_KEYS_ARGON2ID,
  ALLOWED_KEYS_PBKDF2,
  ALLOWED_KEYS_SCRYPT,
  hasExactKeys,
  validateKdfParams,
} from './kdf-policy.js';

/**
 * Vault の `kdf` フィールドに格納するアルゴリズムとパラメータ。`algo` で判別する。
 *
 * アルゴリズムと不整合なパラメータを型で禁止する（KDF パラメータのバージョニング）。
 * 各 `version` は「この SDK のパラメータセット版」であり、Argon2 のアルゴリズム version（0x13 等）とは別概念。
 */
export type KdfParams =
  | { algo: 'argon2id'; version: number; m: number; t: number; p: number } // m: メモリ(KiB) / t: 反復 / p: 並列度
  | { algo: 'scrypt'; version: number; N: number; r: number; p: number } // N: コスト / r: ブロックサイズ / p: 並列度
  | { algo: 'pbkdf2'; version: number; iterations: number }; // iterations: 反復回数

/**
 * K4 ストレージ暗号化鍵の既定 KDF。argon2id, m=19456 KiB(=19 MiB), t=2, p=1。
 *
 * `version: 1` は本 SDK のパラメータセット版であり、@noble の Argon2 アルゴリズム version（既定 0x13）とは別。
 */
export const DEFAULT_KDF: KdfParams = { algo: 'argon2id', version: 1, m: 19456, t: 2, p: 1 };

/** 導出される鍵長（バイト）。AES-256 = 32。 */
export const DERIVED_KEY_LENGTH = 32;

/**
 * KDF パラメータに従いパスワードと salt から 256bit の鍵を導出する。
 *
 * @param kdf 導出に用いる KDF パラメータ。
 * @param password パスワード文字列。
 * @param salt salt（32 バイト）。
 * @returns 32 バイトの導出鍵。
 * @throws 導出に失敗した場合（VericertsError、code `1051`）。秘密は message / context / cause に含めない。
 */
export async function deriveKey(
  kdf: KdfParams,
  password: string,
  salt: Uint8Array,
): Promise<Uint8Array> {
  try {
    const passwordBytes = new TextEncoder().encode(password);
    // salt は呼び出し側で getRandomValues / subarray 由来となり ArrayBufferLike バッキングの
    // 可能性があるため、各バックエンドの BufferSource 要件に合わせてコピーで正規化する。
    const saltSource = Uint8Array.from(salt);
    switch (kdf.algo) {
      case 'argon2id':
        // version は渡さない（@noble 既定 0x13。union の version は本 SDK のパラメータセット版）。
        return await argon2idAsync(passwordBytes, saltSource, {
          m: kdf.m,
          t: kdf.t,
          p: kdf.p,
          dkLen: DERIVED_KEY_LENGTH,
        });
      case 'scrypt':
        return await scryptAsync(passwordBytes, saltSource, {
          N: kdf.N,
          r: kdf.r,
          p: kdf.p,
          dkLen: DERIVED_KEY_LENGTH,
        });
      case 'pbkdf2': {
        const baseKey = await crypto.subtle.importKey('raw', passwordBytes, 'PBKDF2', false, [
          'deriveBits',
        ]);
        const bits = await crypto.subtle.deriveBits(
          { name: 'PBKDF2', salt: saltSource, iterations: kdf.iterations, hash: 'SHA-256' },
          baseKey,
          DERIVED_KEY_LENGTH * 8,
        );
        return new Uint8Array(bits);
      }
    }
  } catch (e) {
    // 自前で投げた VericertsError はそのまま再 throw する。
    if (e instanceof VericertsError) {
      throw e;
    }
    // @noble / Web Crypto 由来の例外は秘密が含まれ得るため cause を渡さず正規化する。
    throw new VericertsError(ErrorCodes.ENCRYPT_FAILED);
  }
}

/**
 * KDF パラメータを JSON（UTF-8）へ直列化する。
 *
 * @param kdf 直列化する KDF パラメータ。
 * @returns UTF-8 エンコードした JSON バイト列。
 */
export function serializeKdf(kdf: KdfParams): Uint8Array {
  return new TextEncoder().encode(JSON.stringify(kdf));
}

/** 値が数値かどうかの型ガード（union 構築時の narrowing 用途）。範囲・整数性は validateKdfParams に一本化。 */
function isNumber(value: unknown): value is number {
  return typeof value === 'number';
}

/**
 * JSON（UTF-8）バイト列を KDF パラメータへ復元し、許可キー一致と確定パラメータを検証する。
 *
 * (a) 生 JSON のキー集合が algo 別許可キー集合と完全一致しなければ拒否（unknown / 欠落キー拒否）。
 * (b) union 構築後、return 直前に `validateKdfParams` で範囲・整数性・最低コスト・version を検証する。
 *
 * @param json `serializeKdf` 由来の JSON バイト列。
 * @returns 検証済みの KDF パラメータ。
 * @throws 不正な algo / キー不一致 / 範囲・整数性違反 / JSON パース失敗の場合（VericertsError、code `1050`）。
 */
export function parseKdf(json: Uint8Array): KdfParams {
  let parsed: unknown;
  try {
    parsed = parseJsonWithoutPrototype(new TextDecoder().decode(json));
  } catch {
    // パース対象に秘密は含まれ得るため cause を渡さない。
    throw new VericertsError(ErrorCodes.DECRYPT_FAILED);
  }
  if (typeof parsed !== 'object' || parsed === null) {
    throw new VericertsError(ErrorCodes.DECRYPT_FAILED);
  }
  const obj = parsed as Record<string, unknown>;
  let kdf: KdfParams;
  switch (obj.algo) {
    case 'argon2id':
      if (
        hasExactKeys(obj, ALLOWED_KEYS_ARGON2ID) &&
        isNumber(obj.version) &&
        isNumber(obj.m) &&
        isNumber(obj.t) &&
        isNumber(obj.p)
      ) {
        kdf = { algo: 'argon2id', version: obj.version, m: obj.m, t: obj.t, p: obj.p };
        break;
      }
      throw new VericertsError(ErrorCodes.DECRYPT_FAILED);
    case 'scrypt':
      if (
        hasExactKeys(obj, ALLOWED_KEYS_SCRYPT) &&
        isNumber(obj.version) &&
        isNumber(obj.N) &&
        isNumber(obj.r) &&
        isNumber(obj.p)
      ) {
        kdf = { algo: 'scrypt', version: obj.version, N: obj.N, r: obj.r, p: obj.p };
        break;
      }
      throw new VericertsError(ErrorCodes.DECRYPT_FAILED);
    case 'pbkdf2':
      if (
        hasExactKeys(obj, ALLOWED_KEYS_PBKDF2) &&
        isNumber(obj.version) &&
        isNumber(obj.iterations)
      ) {
        kdf = { algo: 'pbkdf2', version: obj.version, iterations: obj.iterations };
        break;
      }
      throw new VericertsError(ErrorCodes.DECRYPT_FAILED);
    default:
      throw new VericertsError(ErrorCodes.DECRYPT_FAILED);
  }
  // 範囲・整数性・最低コスト・version の検証は validateKdfParams に一本化する。
  validateKdfParams(kdf, ErrorCodes.DECRYPT_FAILED);
  return kdf;
}

// 暗号化エンベロープの byte 列 pack/unpack は vault/envelope-format.ts へ分離した（本ファイルからの
// 再エクスポートはしない: 本ファイルは vault/envelope-format.ts から parseKdf を参照されるため、
// 逆方向の re-export は循環 import になる）。呼び出し側は vault/envelope-format.js を直接 import する。
