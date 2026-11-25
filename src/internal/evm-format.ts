/**
 * EVM アドレス / CAIP-2 chainId 参照部の形式検証の SSOT。
 *
 * アドレス（9 箇所）と CAIP-2 chainId 参照部（3 箇所）の形式判定が独立実装され食い違っていたため
 * （`method-pkh.ts` の旧 `/^[0-9]+$/` だけが先頭ゼロを許容）、先頭ゼロ拒否の正準形（`did-ethr.ts` /
 * `did-url.ts`）へ統一して集約した。
 *
 * アドレス判定は、大文字小文字が混在する表記に限り EIP-55 チェックサムを検証する。全小文字・全大文字は
 * 形式のみ検証する。siwe.ts の `ethers.isAddress` は ethers/viem 非依存の本モジュールと目的が異なり統合しない。
 *
 * extension は tsconfig の paths（`vericerts-wallet-sdk/evm-format`）経由で本モジュールを直接参照する
 * （`pin-policy.ts` 等、既存の internal モジュール共有と同じ方式）。
 */

import { keccak_256 } from '@noble/hashes/sha3.js';
import { ownProperty } from './prototype-safety/own-property.js';

/** `0x` プレフィックス付き 20 バイト（40 hex 桁）アドレスの形式パターン（大小文字許容）。 */
const EVM_ADDRESS_PATTERN = /^0x[0-9a-fA-F]{40}$/;

/** CAIP-2 chainId 参照部（10 進数の数字列、先頭ゼロ不可の正準形）の形式パターン。 */
const CAIP2_CHAIN_ID_PATTERN = /^(?:0|[1-9][0-9]*)$/;

/** 任意長 `0x` プレフィックス hex 文字列のパターン（1 桁以上必須）。 */
const HEX_STRING_PATTERN = /^0x[0-9a-fA-F]+$/;

/** 任意長 `0x` プレフィックス hex 文字列のパターン（`0x` のみ＝桁数 0 も許容）。 */
const HEX_STRING_PATTERN_ALLOW_EMPTY = /^0x[0-9a-fA-F]*$/;

/** 小文字 hex（`0x` なし・40 桁）を EIP-55 チェックサム表記にする（keccak256 の nibble ≥ 8 の英字を大文字化）。 */
export function toEip55Hex(lowerHex: string): string {
  const hash = keccak_256(new TextEncoder().encode(lowerHex));
  let out = '';
  for (let i = 0; i < lowerHex.length; i++) {
    const nibble = ((hash[i >> 1] as number) >> (i % 2 === 0 ? 4 : 0)) & 0x0f;
    out += nibble >= 8 ? lowerHex.charAt(i).toUpperCase() : lowerHex.charAt(i);
  }
  return out;
}

/** EVM アドレスを検証する（`0x` + 40 hex。大文字小文字が混在する表記は EIP-55 チェックサムも検証する）。 */
export function isValidEvmAddress(address: unknown): address is string {
  if (typeof address !== 'string' || !EVM_ADDRESS_PATTERN.test(address)) return false;
  const hex = address.slice(2);
  return (
    hex === hex.toLowerCase() || hex === hex.toUpperCase() || hex === toEip55Hex(hex.toLowerCase())
  );
}

/**
 * CAIP-2 chainId 参照部の形式を検証する（10 進数の数字列、先頭ゼロを拒否する正準形）。
 *
 * @param chainId 検証対象。
 * @returns 形式が正しければ `true`。
 */
export function isValidCaip2ChainId(chainId: unknown): chainId is string {
  return typeof chainId === 'string' && CAIP2_CHAIN_ID_PATTERN.test(chainId);
}

/**
 * `0x` プレフィックス付き任意長 hex 文字列かを検証する（大小文字許容）。
 *
 * `personalSignPayload`（`asset/eth-signing.ts`）にインライン定義されていた正規表現を集約した。
 * 拡張もこの関数を再輸出し、署名時と同じ形式判定を使う。
 *
 * @param value 検証対象。
 * @param options 自身のプロパティ `allowEmpty` で `0x` のみ（hex 桁数 0）を許容する。省略時と継承したプロパティ
 *   （getter を含む）は既定の `false` 扱い。
 * @returns 形式が正しければ `true`。
 */
export function isHexString(
  value: unknown,
  options: { allowEmpty?: boolean } = {},
): value is string {
  if (typeof value !== 'string') return false;
  // 公開 API（/asset）の任意オプションなので、`Object.prototype` 汚染の継承値を拾わないよう own 限定で読む。
  const allowEmpty = ownProperty<boolean>(options, 'allowEmpty');
  return allowEmpty ? HEX_STRING_PATTERN_ALLOW_EMPTY.test(value) : HEX_STRING_PATTERN.test(value);
}
