/**
 * ERC-1056 属性名の解釈と属性値（hex）の復号。
 *
 * 純関数のみで、不正な値は例外ではなく `null` で返す（`buildDidEthrDocument` の「入力起因で投げない」
 * 不変条件のため）。
 */

import { base64, hex } from '@scure/base';

/** 属性名のパース結果。 */
export type ParsedAttributeName =
  | { readonly kind: 'veriKey' | 'sigAuth' | 'ed25519' }
  | { readonly kind: 'service'; readonly serviceType: string };

/**
 * ERC-1056 属性名を解釈する。未知の名前は `null`。対応:
 * - `did/pub/Secp256k1/veriKey/hex`  → veriKey
 * - `did/pub/Secp256k1/sigAuth/hex`  → sigAuth
 * - `did/pub/Ed25519/veriKey/base64` → ed25519
 * - `did/svc/<Type>`                 → service
 */
export function parseAttributeName(name: string): ParsedAttributeName | null {
  if (name === 'did/pub/Secp256k1/veriKey/hex') {
    return { kind: 'veriKey' };
  }
  if (name === 'did/pub/Secp256k1/sigAuth/hex') {
    return { kind: 'sigAuth' };
  }
  if (name === 'did/pub/Ed25519/veriKey/base64') {
    return { kind: 'ed25519' };
  }
  if (name.startsWith('did/svc/')) {
    return { kind: 'service', serviceType: name.slice('did/svc/'.length) };
  }
  return null;
}

/** `0x` 付き hex を `0x` 付きの正規化済み hex 文字列にする（保持・小文字化なし）。 */
export function normalizeHex(value: string): string {
  return value.startsWith('0x') ? value : `0x${value}`;
}

/**
 * `0x` 付き hex 文字列をバイト列へ変換する（`@scure/base` の hex）。
 * `hex.decode` は奇数長・非 hex で throw するため、失敗時は `null` を返す
 * （buildDidEthrDocument の「例外を投げない」不変条件のため）。
 */
function hexToBytes(value: string): Uint8Array | null {
  try {
    return hex.decode(value.startsWith('0x') ? value.slice(2) : value);
  } catch {
    return null;
  }
}

/** hex 値（鍵バイト）を base64 文字列に変換する（Ed25519 publicKeyBase64 用）。失敗は `null`。 */
export function hexToBase64(value: string): string | null {
  const bytes = hexToBytes(value);
  return bytes === null ? null : base64.encode(bytes);
}

/**
 * service の serviceEndpoint を value（hex）から復元する。デコード失敗は `null`。
 * 現状は value を UTF-8 文字列（URL 等）として返す。構造化エンドポイント
 * （JSON object 等）への対応は将来課題。
 */
export function decodeServiceEndpoint(value: string): string | null {
  const bytes = hexToBytes(value);
  return bytes === null ? null : new TextDecoder('utf-8').decode(bytes);
}
