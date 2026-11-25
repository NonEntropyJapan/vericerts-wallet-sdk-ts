/**
 * SIWE（EIP-4361）メッセージへの ERC-191（`personal_sign` 相当）署名の生成。
 *
 * `siwe.ts`（メッセージ生成 / パース / 検証）とは別ファイルに分離する。`siwe.ts` は `ethers` /
 * `viem/siwe` を bare import するが、extension は ethers / viem をバンドルしない方針である。
 * 署名生成自体は ERC-191 のバイト列組み立て
 * （`asset/eth-signing.ts`、@noble/@scure のみに閉じる）と `Signer`（keymanager.ts）だけで完結するため、
 * 本ファイルを ethers/viem 非依存に保てば extension から直接 alias できる。
 */

import { formatEthereumSignature, personalSignPayload } from '../../asset/eth-signing.js';
import type { Signer } from '../../keymanager/types.js';

/**
 * SIWE メッセージに ERC-191（`personal_sign` 相当）署名を生成する。
 *
 * `signer` は `KeyManager.getSigner(keyID)` で解決済みの署名インターフェース。生鍵を扱わず、
 * `issueCredential` 等 SDK 内の他の署名 API と同じ「呼び出し側が keyID → Signer を解決してから
 * 渡す」規約に揃える（鍵未検出は `KeyManager.getSigner` 側で 1004 として throw 済み）。
 *
 * @param message `generateSiweMessage` が返す EIP-4361 準拠メッセージ文字列。
 * @param signer 署名に使う鍵（`KeyManager.getSigner(keyID)` の戻り値）。
 * @returns ERC-191 準拠の署名文字列（`0x` + 130 hex）。
 *   `verifyEoaSignature(message, signature, signer.address())` で検証できる。
 */
export async function signSIWE(message: string, signer: Signer): Promise<string> {
  const signature = await signer.sign(personalSignPayload(message));
  return formatEthereumSignature(signature);
}
