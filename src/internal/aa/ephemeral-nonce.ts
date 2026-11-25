/**
 * SSO 認証回路の nonce クレーム束縛値を SDK 側で
 * 生成する純粋ユーティリティ。
 *
 * ## 何のための値か (swapped-signer 対策)
 * SSO ZK proof はセッション用の ephemeral EOA（signer）に束縛される。id_token の `nonce`
 * クレームに ephemeral signer 由来のコミットメントを埋め込み、回路がそれを `nonceHash` として
 * public 出力し、`ZKValidator` が同じコミットメントをオンチェーンで再計算して
 * `pub[1] (nonceHash) == expectedNonce` を要求することで、proof と UserOp 署名者を束縛する。
 * これにより「他人の valid proof + public 値を、自分の ephemeralSigner + 自分の ECDSA 署名で
 * 再利用する」swapped-signer 攻撃を防ぐ。
 *
 * ## 確定した束縛定義 (SsoSignature.ephemeralCommitment と一致)
 *   `nonce = keccak256(abi.encodePacked(ephemeralSigner)) % r`
 * を、**先頭 0 なしの正準 10 進表記文字列**として id_token の nonce クレームに設定する。
 *   - `ephemeralSigner`: 20 バイトの Ethereum アドレス。`abi.encodePacked(address)` はその
 *     20 バイトそのもの（左詰めパディングなし）。
 *   - `r`: BN254 スカラー域の位数。public signal と同じ域へ還元する。
 *   - 回路は `ExtractDecimalStringClaim` でこの ASCII 数字列を整数化して `nonceHash` に出力する。
 *     `maxNonceDigits = 78`（`keccak%r < 2^254 < 10^77` なので 10 進で最大 77 桁）。
 *
 * ここは snarkjs / Groth16 に依存しない純粋関数（proof 生成本体は別スコープ）。回路の
 * テストベクタ生成時の `ephemeralCommitment(addr)` と、
 * コントラクトの `SsoSignature.ephemeralCommitment` の 3 者で同一定義
 * （`ZKValidator` は同ライブラリを使う側）。
 */

import { ErrorCodes, VericertsError } from '../errors.js';
import { keccak256 } from '../keymanager/address.js';

/**
 * BN254 (alt_bn128) スカラー域の位数 r。
 * `SsoSignature.BN254_SCALAR_FIELD` と一致させること。
 */
export const BN254_SCALAR_FIELD =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

/**
 * `0x` + 40 hex のアドレス文字列を 20 バイトへパースする。
 *
 * EIP-55 チェックサムの大文字小文字は区別しない（`abi.encodePacked(address)` は raw 20 バイトで
 * あり、値のみが束縛に効くため）。長さ・文字種が不正なら例外を投げる。
 *
 * @throws 長さ・文字種が不正な場合（`VericertsError`、code `4070`）。同種の入力を扱う
 *   `aa/user-operation.ts` と同じエラー契約に揃える。
 */
function addressToBytes(address: string): Uint8Array {
  const hex = address.startsWith('0x') || address.startsWith('0X') ? address.slice(2) : address;
  if (hex.length !== 40 || !/^[0-9a-fA-F]{40}$/.test(hex)) {
    throw new VericertsError(ErrorCodes.INVALID_EVM_ADDRESS);
  }
  const bytes = new Uint8Array(20);
  for (let i = 0; i < 20; i++) {
    bytes[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

/**
 * ephemeral signer アドレスから nonce 束縛値（整数）を計算する。
 *
 *   `uint256(keccak256(abi.encodePacked(ephemeralSigner))) % r`
 *
 * @param ephemeralSigner ephemeral EOA アドレス（`0x` + 40 hex, EIP-55 は任意）。
 * @returns BN254 スカラー域に還元した nonce 束縛値。
 * @throws `ephemeralSigner` が `0x` + 40 hex のアドレス形式でない場合（`VericertsError`、code `4070`）。
 */
export function ephemeralNonceValue(ephemeralSigner: string): bigint {
  const digest = keccak256(addressToBytes(ephemeralSigner));
  let value = 0n;
  for (const byte of digest) {
    value = (value << 8n) | BigInt(byte);
  }
  return value % BN254_SCALAR_FIELD;
}

/**
 * ephemeral signer アドレスから id_token の nonce クレームに設定すべき**正準 10 進文字列**を返す。
 *
 * `ephemeralNonceValue` の値を先頭 0 なしの 10 進表記にしたもの。回路は
 * `ExtractDecimalStringClaim` でこの数字列を整数化して `nonceHash` に出力し、`ZKValidator` の
 * オンチェーン再計算値と桁を含め完全一致する。
 *
 * @param ephemeralSigner ephemeral EOA アドレス（`0x` + 40 hex）。
 * @returns 先頭 0 なしの 10 進表記文字列（最大 77 桁）。
 * @throws `ephemeralSigner` が `0x` + 40 hex のアドレス形式でない場合（`VericertsError`、code `4070`）。
 */
export function ephemeralNonceClaim(ephemeralSigner: string): string {
  return ephemeralNonceValue(ephemeralSigner).toString(10);
}
