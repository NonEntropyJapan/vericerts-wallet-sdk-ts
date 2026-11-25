/**
 * SSO 認証回路の `issSubCommitment` public 出力 (`pub[0]`) の束縛値を
 * SDK 側で生成する純粋ユーティリティ。
 *
 * ## 何のための値か (griefing 占有拒否)
 * SSO ZK Validator はアカウントに iss+sub 由来コミットメントを束縛する。この commitment を
 * **オンチェーン再現可能**な keccak256 ベースに確定し、`ZKValidator.onInstall(abi.encode(iss, sub))` が
 * commitment を呼び出し元から受け取らずオンチェーン再計算し、かつ
 * `msg.sender == AccountFactory.deriveAddress(keccak256(iss || 0x00 || sub))` を強制することで、
 * 攻撃者が被害者のカウンターファクチュアルアドレスを別 commitment で占有する griefing を拒否する。
 *
 * ## 確定した束縛定義 (ZKValidator.issSubCommitment と一致)
 *   `issSubCommitment = uint256(keccak256(abi.encodePacked(iss, "\x00", sub))) % r`
 *   - `iss` / `sub`: OIDC issuer / subject 文字列 (UTF-8 バイト列)。
 *   - 区切り子 `0x00`: 長さ拡張衝突を防ぐ (iss="ab",sub="c" と iss="a",sub="bc" を区別。
 *     `AccountFactory.computeSalt` = `keccak256(iss || 0x00 || sub)` と**同一プリイメージ**)。
 *   - `r`: BN254 (alt_bn128) スカラー域の位数。public signal と同じ域へ還元する。
 *
 * この値はアドレス salt `keccak256(iss || 0x00 || sub)` と同一プリイメージから
 * 導出され、`uint256(salt) % r` に等しい。SSO 回路の公開出力と `ZKValidator.onInstall` も同じ定義を使う。
 *
 * ここは snarkjs / Groth16 に依存しない純粋関数 (proof 生成本体は別スコープ)。
 */

import { keccak256 } from '../keymanager/address.js';
import { BN254_SCALAR_FIELD } from './ephemeral-nonce.js';

/** UTF-8 文字列をバイト列へエンコードする。 */
const utf8 = new TextEncoder();

/**
 * iss + sub から `issSubCommitment` (整数) を計算する。
 *
 *   `uint256(keccak256(utf8(iss) || 0x00 || utf8(sub))) % r`
 *
 * `AccountFactory.computeSalt(iss, sub)` = `keccak256(iss || 0x00 || sub)` と同一プリイメージ。
 * 戻り値は `ZKValidator.issSubCommitment(iss, sub)` / `onInstall` がオンチェーンで束縛する値と一致する。
 *
 * `iss` / `sub` 自体に区切り子 `\x00` が含まれると、境界がずれて別の (iss, sub) の組が同一プリイメージ
 * に潰れ衝突し得る (例: iss="A",sub="B\x00C" と iss="A\x00B",sub="C" は共に "A\x00B\x00C" になる)。
 * `AccountFactory.computeSalt` 側はこれを revert で拒否するため、ここでも同じ入力を拒否して
 * オンチェーンの前提と整合させる。
 *
 * @param iss OIDC issuer 文字列 (例: `https://accounts.google.com`)。`\x00` を含むと throw する。
 * @param sub OIDC subject 文字列。`\x00` を含むと throw する。
 * @returns BN254 スカラー域に還元した issSubCommitment 束縛値。
 * @throws {Error} `iss` または `sub` の UTF-8 バイト列に `0x00` が含まれる場合。
 */
export function issSubCommitmentValue(iss: string, sub: string): bigint {
  const issBytes = utf8.encode(iss);
  const subBytes = utf8.encode(sub);
  if (issBytes.includes(0x00) || subBytes.includes(0x00)) {
    throw new Error(
      'issSubCommitmentValue: iss/sub must not contain a NUL byte (0x00); it collides with the ' +
        '"\\x00" delimiter used to prevent preimage collisions (matches AccountFactory.computeSalt).',
    );
  }
  const preimage = new Uint8Array(issBytes.length + 1 + subBytes.length);
  preimage.set(issBytes, 0);
  preimage[issBytes.length] = 0x00; // 区切り子
  preimage.set(subBytes, issBytes.length + 1);

  const digest = keccak256(preimage);
  let value = 0n;
  for (const byte of digest) {
    value = (value << 8n) | BigInt(byte);
  }
  return value % BN254_SCALAR_FIELD;
}

/**
 * iss + sub から issSubCommitment の**正準 10 進文字列**を返す。
 *
 * `issSubCommitmentValue` の値を先頭 0 なしの 10 進表記にしたもの。
 *
 * @param iss OIDC issuer 文字列。
 * @param sub OIDC subject 文字列。
 * @returns 先頭 0 なしの 10 進表記文字列。
 */
export function issSubCommitmentClaim(iss: string, sub: string): string {
  return issSubCommitmentValue(iss, sub).toString(10);
}
