/**
 * W2W バックアップの鍵導出パラメータ（PBKDF2-SHA-256）。
 *
 * `exportBackup` / `importBackup` の双方が同じ値・同じ組み立てを使う必要があるため
 * （食い違うと復号できない、あるいは弱いパラメータで導出される）、`backup.ts` から切り出して
 * 単一ソースにしている。
 */

import type { KdfParams } from '../../keymanager/kdf.js';

/** PBKDF2 のデフォルト反復回数（kdfParams.iterations 相当）。 */
export const DEFAULT_PBKDF2_ITERATIONS = 600_000;

/**
 * PBKDF2 反復回数の上限。JWE の protected header は署名検証より前に読まれるため、上限がないと
 * 巨大な `iterations` で呼び出し側スレッドを占有できてしまう（DoS）。
 *
 * これは W2W バックアップモジュール固有の**資源上限**であり、セキュリティ下限のポリシーではない。
 * KeyManager の K4 保存鍵ポリシー（`keymanager/kdf-policy.ts` の `PBKDF2_ITER_MIN` /
 * `PBKDF2_ITER_MAX`）とは対象サブシステムも脅威モデルも異なるため意図的に独立させている
 * （W2W は Wallet-Swap の UX と既存の低反復テストフィクスチャとの互換のため低い下限を許す）。
 * W2W 側の下限を引き上げる場合は本コメントの含意ではなく、独立した課題として判断すること。
 */
export const MAX_PBKDF2_ITERATIONS = 10_000_000;

/**
 * PBKDF2 反復回数として受理できる値か（エクスポート側・インポート側で共有する唯一の定義）。
 *
 * @param n 検査する反復回数。
 * @returns 1 以上 `MAX_PBKDF2_ITERATIONS` 以下の整数なら true。
 */
export function isValidPbkdf2Iterations(n: number): boolean {
  return Number.isInteger(n) && n >= 1 && n <= MAX_PBKDF2_ITERATIONS;
}

/** salt 長（バイト）。kdf.ts と揃えて 256bit = 32 バイト。 */
export const SALT_LENGTH = 32;

/**
 * PBKDF2-SHA-256 用の KDF パラメータを組み立てる。
 *
 * @param iterations 反復回数。
 * @returns kdf.ts の `deriveKey` に渡す KdfParams。
 */
export function pbkdf2Params(iterations: number): KdfParams {
  return { algo: 'pbkdf2', version: 1, iterations };
}
