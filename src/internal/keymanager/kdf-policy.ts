/**
 * KDF パラメータの妥当性ポリシー。
 *
 * 認証前 DoS（巨大 m / N / iterations による鍵導出での資源枯渇）を防ぐため、暗号化・復号双方で
 * 鍵導出（deriveKey）に渡す前に KDF パラメータの上限・整数性・最低コストを検証する。
 *
 * 確定パラメータ:
 * - argon2id: `p` 1-4 / `m >= 8*p` かつ `m <= 65536` / `t` 1-4。さらに OWASP 最低コスト保証。
 * - scrypt: `r === 8` / `p` 1-10 / `N` は 2^14..2^17 の 2 冪 / `N*p <= 2^17`。
 * - pbkdf2: `iterations` 600_000..2_000_000。
 * - 全数値は `Number.isSafeInteger` 必須。`version` は `1` のみ許可。
 *
 * セキュリティ上の注意:
 * - throw は引数なし（password / salt / 鍵 / 平文 / 巨大値など秘密・入力を message / context に含めない）。
 */

import { type ErrorCode, VericertsError } from '../errors.js';
import type { KdfParams } from './kdf.js';

/** argon2id メモリコスト `m`（KiB）の上限。 */
export const ARGON2ID_M_MAX = 65536;
/** argon2id 反復回数 `t` の上限。 */
export const ARGON2ID_T_MAX = 4;
/** argon2id 並列度 `p` の上限。 */
export const ARGON2ID_P_MAX = 4;
/** scrypt コストパラメータ `N` の下限（2^14）。 */
export const SCRYPT_N_MIN = 1 << 14;
/** scrypt コストパラメータ `N` の上限（2^17）。 */
export const SCRYPT_N_MAX = 1 << 17;
/** scrypt の総コスト `N*p` の上限（2^17）。 */
export const SCRYPT_NP_MAX = 1 << 17;
/**
 * scrypt 並列度 `p` の上限。OWASP 上の独立上限であり、`N >= 2^14` かつ `N*p <= 2^17` の制約下では
 * 実効上限は p<=8 までしか成立しない（10 は名目上の上限）。
 */
export const SCRYPT_P_MAX = 10;
/** pbkdf2 反復回数の下限。 */
export const PBKDF2_ITER_MIN = 600_000;
/** pbkdf2 反復回数の上限。 */
export const PBKDF2_ITER_MAX = 2_000_000;

/** argon2id で許可するキー集合（生 JSON のキーと完全一致を要求する用途）。 */
export const ALLOWED_KEYS_ARGON2ID = ['algo', 'version', 'm', 't', 'p'] as const;
/** scrypt で許可するキー集合。 */
export const ALLOWED_KEYS_SCRYPT = ['algo', 'version', 'N', 'r', 'p'] as const;
/** pbkdf2 で許可するキー集合。 */
export const ALLOWED_KEYS_PBKDF2 = ['algo', 'version', 'iterations'] as const;

/** 生 JSON のキー集合が許可キー集合と完全一致するか判定する（unknown / 欠落キー拒否）。 */
export function hasExactKeys(obj: Record<string, unknown>, allowed: readonly string[]): boolean {
  const keys = Object.keys(obj);
  return keys.length === allowed.length && allowed.every((k) => Object.hasOwn(obj, k));
}

/** 安全整数かつ指定範囲（両端含む）に収まるか判定する。 */
function isInRange(value: number, min: number, max: number): boolean {
  return Number.isSafeInteger(value) && value >= min && value <= max;
}

/** 2 の冪乗（正の整数）かどうかを判定する。 */
function isPowerOfTwo(value: number): boolean {
  return Number.isSafeInteger(value) && value > 0 && (value & (value - 1)) === 0;
}

/**
 * argon2id が OWASP 最低コストを満たすか判定する。
 *
 * いずれかの組み合わせを満たせば可: `(m>=19456&&t>=2) || (m>=12288&&t>=3) ||
 * (m>=9216&&t>=4) || (m>=7168&&t>=5)`。
 */
function meetsArgon2idMinCost(m: number, t: number): boolean {
  return (
    (m >= 19456 && t >= 2) ||
    (m >= 12288 && t >= 3) ||
    (m >= 9216 && t >= 4) ||
    (m >= 7168 && t >= 5)
  );
}

/**
 * KDF パラメータを確定パラメータで検証する。違反時は引数なしで `VericertsError` を投げる。
 *
 * 復号時は OWASP の最低コストを満たす複数の Argon2id プロファイルを受理する
 * （例: m=9216 KiB、t=4、p=1）。新規エンベロープの既定値は `DEFAULT_KDF`
 * （m=19456 KiB、t=2、p=1）。
 *
 * @param kdf 検証対象の KDF パラメータ。
 * @param errorCode 違反時に投げるエラーコード（encrypt 経路は 1051 / decrypt 経路は 1050）。
 * @throws version / 範囲 / 整数性 / 最低コスト / 2 冪 / 未知 algo 違反の場合（VericertsError）。
 */
export function validateKdfParams(kdf: KdfParams, errorCode: ErrorCode): void {
  if (!(Number.isSafeInteger(kdf.version) && kdf.version === 1)) {
    throw new VericertsError(errorCode);
  }
  switch (kdf.algo) {
    case 'argon2id': {
      const { m, t, p } = kdf;
      const ok =
        isInRange(p, 1, ARGON2ID_P_MAX) &&
        isInRange(t, 1, ARGON2ID_T_MAX) &&
        isInRange(m, 8 * p, ARGON2ID_M_MAX) &&
        meetsArgon2idMinCost(m, t);
      if (!ok) {
        throw new VericertsError(errorCode);
      }
      return;
    }
    case 'scrypt': {
      const { N, r, p } = kdf;
      const ok =
        r === 8 &&
        isInRange(p, 1, SCRYPT_P_MAX) &&
        isInRange(N, SCRYPT_N_MIN, SCRYPT_N_MAX) &&
        isPowerOfTwo(N) &&
        Number.isSafeInteger(N * p) &&
        N * p <= SCRYPT_NP_MAX;
      if (!ok) {
        throw new VericertsError(errorCode);
      }
      return;
    }
    case 'pbkdf2': {
      if (!isInRange(kdf.iterations, PBKDF2_ITER_MIN, PBKDF2_ITER_MAX)) {
        throw new VericertsError(errorCode);
      }
      return;
    }
    default:
      // 未知 algo は型上到達しないが、防御的に拒否する。
      throw new VericertsError(errorCode);
  }
}

/**
 * KDF パラメータを exact-key 一致と確定パラメータで検証し、正規化済みの新しい plain object を返す。
 *
 * 外部 mutable 参照を断つため、入力をそのまま保持せず `switch(algo)` で許可キーのみを明示構築した
 * 新オブジェクトを返す（構築後に呼び出し側が元参照を変更しても影響しない＝TOCTOU 防御）。
 * `JSON.parse(JSON.stringify())` は使わず、型安全に再構築する。
 *
 * (a) exact-key チェック: algo 別許可キー集合と完全一致しない（unknown / 欠落キー・未知 algo）場合は拒否。
 * (b) `validateKdfParams` で範囲・整数性・version・最低コスト・2 冪を検証。
 *
 * @param kdf 検証・正規化対象の KDF パラメータ。
 * @param errorCode 違反時に投げるエラーコード（構築・encrypt 経路は 1051）。
 * @returns 許可キーのみで再構築した正規化済み KDF パラメータ。
 * @throws exact-key 不一致 / 範囲・整数性 / version / 最低コスト / 2 冪 / 未知 algo 違反の場合（VericertsError）。
 */
export function canonicalizeKdfParams(kdf: KdfParams, errorCode: ErrorCode): KdfParams {
  const obj = kdf as unknown as Record<string, unknown>;
  switch (kdf.algo) {
    case 'argon2id':
      if (!hasExactKeys(obj, ALLOWED_KEYS_ARGON2ID)) {
        throw new VericertsError(errorCode);
      }
      break;
    case 'scrypt':
      if (!hasExactKeys(obj, ALLOWED_KEYS_SCRYPT)) {
        throw new VericertsError(errorCode);
      }
      break;
    case 'pbkdf2':
      if (!hasExactKeys(obj, ALLOWED_KEYS_PBKDF2)) {
        throw new VericertsError(errorCode);
      }
      break;
    default:
      // 未知 algo は型上到達しないが、防御的に拒否する。
      throw new VericertsError(errorCode);
  }
  validateKdfParams(kdf, errorCode);
  switch (kdf.algo) {
    case 'argon2id':
      return { algo: 'argon2id', version: kdf.version, m: kdf.m, t: kdf.t, p: kdf.p };
    case 'scrypt':
      return { algo: 'scrypt', version: kdf.version, N: kdf.N, r: kdf.r, p: kdf.p };
    case 'pbkdf2':
      return { algo: 'pbkdf2', version: kdf.version, iterations: kdf.iterations };
  }
}
