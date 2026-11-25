/**
 * SIWE 署名検証。EOA（ERC-191 Personal Sign）と AA スマートアカウント（ERC-1271）の
 * 両経路を提供する。
 *
 * ライブラリ方針:
 * - ERC-191 署名からのアドレス復元は `ethers` の `verifyMessage` / メッセージハッシュは `hashMessage`。
 * - ERC-1271 の `isValidSignature` 呼び出しは siwe.ts の `Erc1271Rpc` seam 経由でのみ行う（テスト注入可）。
 *
 * セキュリティ上の注意:
 * - アドレス・署名・メッセージ本文・RPC 応答を VericertsError の message / context / cause に伝播させない。
 */

import { hashMessage, verifyMessage } from 'ethers';
import { ErrorCodes, VericertsError } from '../../errors.js';
import { ERC1271_MAGIC_VALUE, type Erc1271Rpc, type Hex, toChecksumAddress } from './siwe.js';

/** ERC-1271 の `isValidSignature(bytes32,bytes)` セレクタ（keccak256 の先頭 4 バイト）。 */
const ERC1271_SELECTOR = '0x1626ba7e';
/** 署名バイト列（`0x` + 偶数個の hex）の許容パターン。 */
const HEX_BYTES_PATTERN = /^0x([0-9a-fA-F]{2})*$/;
/** ABI ワード（32 byte = 64 hex 文字）。 */
const WORD_HEX = 64;

/**
 * EOA（外部所有アカウント）の ERC-191 Personal Sign 署名を検証する。
 *
 * 署名から復元したアドレスが期待アドレス（ERC-55 正規化後）と一致すれば true。
 *
 * @param message 署名対象の SIWE メッセージ文字列。
 * @param signature 65 byte の ECDSA 署名（`0x` + 130 hex）。
 * @param expectedAddress 期待する署名者アドレス。
 * @returns 一致すれば true、不一致なら false。
 * @throws アドレス形式不正（4070）。署名復元不能は false を返す。
 */
export function verifyEoaSignature(
  message: string,
  signature: string,
  expectedAddress: string,
): boolean {
  const expected = toChecksumAddress(expectedAddress);
  let recovered: string;
  try {
    recovered = verifyMessage(message, signature);
  } catch {
    return false;
  }
  return recovered === expected;
}

/**
 * ERC-1271 でスマートコントラクトウォレット（AA アカウント）の署名を検証する。
 *
 * SIWE メッセージの ERC-191 ハッシュを算出し、`account.isValidSignature(hash, signature)` を
 * `Erc1271Rpc` seam 経由で呼ぶ。返り値の magicValue が `0x1626ba7e` であれば有効とみなす。
 *
 * @param rpc ERC-1271 呼び出しの seam（既定実装は siwe-erc1271-adapter.ts）。
 * @param message 署名対象の SIWE メッセージ文字列。
 * @param signature スマートアカウントが受理する署名バイト列（`0x` プレフィックス付き hex）。
 * @param account 検証対象のスマートアカウントアドレス。
 * @returns magicValue が一致すれば true、それ以外は false。
 * @throws アドレス / 署名形式不正（4070）、eth_call 失敗（1021）。
 */
export async function verifyErc1271Signature(
  rpc: Erc1271Rpc,
  message: string,
  signature: Hex,
  account: string,
): Promise<boolean> {
  const to = toChecksumAddress(account);
  // 署名は `0x` + 偶数個 hex（バイト列）でなければならない。専用の署名形式コードが無いため、
  // アドレス/入力形式エラーと同じ 4070（INVALID_EVM_ADDRESS）に正規化する。
  if (typeof signature !== 'string' || !HEX_BYTES_PATTERN.test(signature)) {
    throw new VericertsError(ErrorCodes.INVALID_EVM_ADDRESS);
  }
  const hash = hashMessage(message) as Hex;
  const data = encodeIsValidSignatureCall(hash, signature);
  const result = await rpc.call(to, data);
  return normalizeMagicValue(result) === ERC1271_MAGIC_VALUE;
}

/**
 * `isValidSignature(bytes32,bytes)` の calldata を ABI エンコードする。
 * レイアウト: selector(4) | hash(32) | offset(32) | length(32) | signature(padded 32 の倍数)。
 */
function encodeIsValidSignatureCall(hash: Hex, signature: Hex): Hex {
  const sigHex = signature.slice(2);
  const sigLenBytes = sigHex.length / 2;
  const offset = (64).toString(16).padStart(WORD_HEX, '0'); // hash の次（0x40）
  const length = sigLenBytes.toString(16).padStart(WORD_HEX, '0');
  const padded = sigHex.padEnd(Math.ceil(sigHex.length / WORD_HEX) * WORD_HEX, '0');
  return `${ERC1271_SELECTOR}${hash.slice(2)}${offset}${length}${padded}` as Hex;
}

/** eth_call の返り値から先頭 4 byte（bytes4 magicValue）を取り出して小文字化する。 */
function normalizeMagicValue(result: Hex): string {
  if (typeof result !== 'string' || !result.startsWith('0x') || result.length < 10) {
    return '';
  }
  return `0x${result.slice(2, 10).toLowerCase()}`;
}
