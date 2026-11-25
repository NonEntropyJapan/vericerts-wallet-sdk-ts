/**
 * ダイジェスト文字列（hex / base64url / multibase）のデコード。
 *
 * `<alg>-<digest>` の `<digest>` 部は
 * 実運用で hex・base64url・multibase の 3 通りが現れるため、いずれも同じバイト列へ落とす。
 *
 * 判定は「復号後の長さがアルゴリズム既定のダイジェスト長と一致すること」を必須条件とした
 * fail-closed とし、以下の優先順で試す（曖昧さを消すため順序を固定する）:
 *   1. hex（`2 * digestLength` 文字ちょうど、大文字小文字どちらも可）
 *   2. base64url（padding あり / なし）
 *   3. multibase（先頭 1 文字のプレフィックスで基数を決定）
 *
 * `@scure/base` 由来の例外はメッセージに入力を含み得るため、`cause` を渡さず握りつぶす。
 */

import { base32nopad, base58, base64nopad, base64urlnopad, hex } from '@scure/base';
import { MAX_BASE58_TEXT_LENGTH } from '../multibase.js';

/**
 * contentHash 表記・multibase 文字列の最大文字数。
 *
 * `@scure/base` の base58 デコードは入力長に対して二次時間（`z`×100,000 で約 16 秒）で、
 * contentHash クレームや DID 末尾セグメントは署名検証前の攻撃者制御入力のため、デコード前に
 * 長さで打ち切る。正当な表記（`sha2-256-` + hex 64 文字 / multibase multihash 34 バイト /
 * CIDv1）は 100 文字前後に収まるため、 base58 上限（{@link MAX_BASE58_TEXT_LENGTH}）を再利用する。
 */
export const MAX_CONTENT_HASH_TEXT_LENGTH = MAX_BASE58_TEXT_LENGTH;

/** multibase プレフィックス文字 → デコーダ。プロトタイプ経由のヒットを塞ぐ。 */
const MULTIBASE_DECODERS: Record<string, ((body: string) => Uint8Array) | undefined> =
  Object.assign(Object.create(null), {
    // base16（`f` = 小文字 / `F` = 大文字）。
    f: (body: string) => hex.decode(body.toLowerCase()),
    F: (body: string) => hex.decode(body.toLowerCase()),
    // base32 RFC4648 padding なし（`b` = 小文字 / `B` = 大文字）。@scure は大文字アルファベット。
    b: (body: string) => base32nopad.decode(body.toUpperCase()),
    B: (body: string) => base32nopad.decode(body.toUpperCase()),
    // base64 / base64pad。padding は事前に除去して nopad デコーダへ渡す。
    m: (body: string) => base64nopad.decode(body),
    M: (body: string) => base64nopad.decode(stripPadding(body)),
    // base64url / base64urlpad。
    u: (body: string) => base64urlnopad.decode(body),
    U: (body: string) => base64urlnopad.decode(stripPadding(body)),
    // base58btc。
    z: (body: string) => base58.decode(body),
  });

/** base64 系の `=` padding を除去する。 */
function stripPadding(text: string): string {
  return text.replace(/=+$/, '');
}

/** 文字列全体が hex（大文字小文字混在可）かどうか。 */
function isHex(text: string): boolean {
  return /^[0-9a-fA-F]+$/.test(text);
}

/**
 * hex としてデコードを試みる。
 *
 * 長さが `2 * expectedLength` ちょうどの場合のみ受理する。base64url との取り違えを防ぐため、
 * 長さが合わない hex 風文字列は「hex ではない」として次の候補へ回す。
 */
function tryHex(text: string, expectedLength: number): Uint8Array | undefined {
  if (text.length !== expectedLength * 2 || !isHex(text)) {
    return undefined;
  }
  try {
    return hex.decode(text.toLowerCase());
  } catch {
    return undefined;
  }
}

/** base64url（padding あり / なし）としてデコードを試みる。 */
function tryBase64Url(text: string, expectedLength: number): Uint8Array | undefined {
  const body = stripPadding(text);
  if (body.length !== text.length && text.length % 4 !== 0) {
    // padding 付きを名乗るなら 4 の倍数長でなければならない。
    return undefined;
  }
  try {
    const bytes = base64urlnopad.decode(body);
    return bytes.length === expectedLength ? bytes : undefined;
  } catch {
    return undefined;
  }
}

/** multibase としてデコードを試みる。 */
function tryMultibase(text: string, expectedLength: number): Uint8Array | undefined {
  const prefix = text.slice(0, 1);
  const decode = MULTIBASE_DECODERS[prefix];
  if (decode === undefined) {
    return undefined;
  }
  const body = text.slice(1);
  if (body.length === 0) {
    return undefined;
  }
  try {
    const bytes = decode(body);
    return bytes.length === expectedLength ? bytes : undefined;
  } catch {
    return undefined;
  }
}

/**
 * ダイジェスト文字列を指定長のバイト列へデコードする。
 *
 * @param text hex / base64url / multibase のいずれかで表現されたダイジェスト。
 * @param expectedLength 期待するバイト長（アルゴリズム既定値）。
 * @returns デコードしたバイト列。どの表記でも `expectedLength` にならない場合は `undefined`。
 */
export function decodeDigest(text: string, expectedLength: number): Uint8Array | undefined {
  if (text.length === 0 || text.length > MAX_CONTENT_HASH_TEXT_LENGTH) {
    return undefined;
  }
  return (
    tryHex(text, expectedLength) ??
    tryBase64Url(text, expectedLength) ??
    tryMultibase(text, expectedLength)
  );
}

/**
 * multibase 文字列をデコードする（multihash バイト列の取り出し用）。デコード結果の長さ制約はないが、
 * 入力は {@link MAX_CONTENT_HASH_TEXT_LENGTH} 文字まで。
 *
 * @param text multibase 文字列（先頭 1 文字が基数プレフィックス）。
 * @returns デコードしたバイト列。未知プレフィックス / 不正エンコード / 長さ超過なら `undefined`。
 */
export function decodeMultibase(text: string): Uint8Array | undefined {
  if (text.length > MAX_CONTENT_HASH_TEXT_LENGTH) {
    return undefined;
  }
  const prefix = text.slice(0, 1);
  const decode = MULTIBASE_DECODERS[prefix];
  if (decode === undefined) {
    return undefined;
  }
  const body = text.slice(1);
  if (body.length === 0) {
    return undefined;
  }
  try {
    return decode(body);
  } catch {
    return undefined;
  }
}

/**
 * バイト列を小文字 hex へエンコードする（canonical 表記の生成用）。
 *
 * @param bytes エンコード対象。
 * @returns 小文字 hex 文字列。
 */
export function encodeHex(bytes: Uint8Array): string {
  return hex.encode(bytes);
}
