/**
 * Multibase（base58btc）と Multicodec varint プレフィックスの低レベルヘルパ。
 *
 * `did:key` 識別子は `multibase(base58btc, multicodec_prefix || raw_public_key_bytes)` で
 * 構成される。本モジュールは以下のみを担当する:
 * - Multicodec コード（unsigned LEB128 varint）のエンコード。
 * - base58btc multibase の `z` プレフィックス付与（encode）/ 前提・除去（decode）。
 *
 * base58 の実装は `@scure/base` の `base58`（Bitcoin アルファベット）に委ねる。新規ライブラリ
 * （multiformats 等）は導入しない。
 *
 * セキュリティ上の注意:
 * - 例外メッセージや `context` に DID 文字列・公開鍵バイトなどの入力データを含めない。
 * - `@scure/base` 由来の例外はメッセージに入力が含まれ得るため、`cause` を渡さず
 *   `VericertsError`（code `2001`）へ正規化する。
 */

import { base58 } from '@scure/base';
import { ErrorCodes, VericertsError } from '../errors.js';

/** Multibase base58btc を表すプレフィックス文字（`z`）。 */
const BASE58BTC_PREFIX = 'z';

/**
 * {@link multibaseBase58Decode} が既定で受理する `z` + 本文の最大文字数。
 *
 * `@scure/base` の base58 デコードは入力長に対して二次時間（`Z`×100,000 で約 18 秒）であり、
 * 署名検証前の DID（`iss` / `kid`）が攻撃者制御のため、デコード前に長さで打ち切る。
 * 公開鍵（did:key / Multikey は 60 文字程度）・multihash・Ed25519 署名（約 90 文字）はいずれも
 * 余裕をもってこの値に収まる。これを超える入力（did:peer:4 のドキュメント）だけが用途別の
 * 上限を明示的に渡す。
 */
export const MAX_BASE58_TEXT_LENGTH = 512;

/**
 * Multicodec コードを unsigned LEB128 varint としてエンコードする。
 *
 * did:key で使う 3 種（`0xed01` Ed25519 / `0xe701` secp256k1 / `0x1200` P-256）は
 * いずれも 2 バイトに収まる。汎用の unsigned LEB128 として実装する。
 *
 * @param codec Multicodec コード（非負整数）。
 * @returns varint バイト列（little-endian の 7bit グループ、各バイト上位ビットが継続フラグ）。
 */
export function encodeMulticodecVarint(codec: number): Uint8Array {
  const bytes: number[] = [];
  let value = codec;
  do {
    // 下位 7bit を取り出し、残りがあれば継続ビット（0x80）を立てる。
    let byte = value & 0x7f;
    value >>>= 7;
    if (value !== 0) {
      byte |= 0x80;
    }
    bytes.push(byte);
  } while (value !== 0);
  return Uint8Array.from(bytes);
}

/**
 * バイト列を multibase base58btc（`z` プレフィックス付き）でエンコードする。
 *
 * @param bytes エンコード対象のバイト列。
 * @returns `z` + base58btc 文字列。
 */
export function multibaseBase58Encode(bytes: Uint8Array): string {
  return BASE58BTC_PREFIX + base58.encode(bytes);
}

/**
 * multibase base58btc（`z` プレフィックス前提）文字列をバイト列へデコードする。
 *
 * `z` 以外のプレフィックス、または base58 として不正な文字列は DID 形式不正
 * （code `2001`）に正規化する。
 *
 * 二次時間のデコードに入る前に `text.length` が `maxLength` を超えるものを拒否する。
 *
 * @param text `z` + base58btc 文字列。
 * @param maxLength 受理する `text` の最大文字数（`z` を含む）。既定は {@link MAX_BASE58_TEXT_LENGTH}。
 * @returns デコードしたバイト列。
 * @throws `z` 始まりでない / base58 不正 / 長さ超過の場合（VericertsError、code `2001`）。
 */
export function multibaseBase58Decode(
  text: string,
  maxLength: number = MAX_BASE58_TEXT_LENGTH,
): Uint8Array {
  if (text.length > maxLength || !text.startsWith(BASE58BTC_PREFIX)) {
    // 入力文字列はメッセージに含めない。
    throw new VericertsError(ErrorCodes.INVALID_DID);
  }
  const body = text.slice(BASE58BTC_PREFIX.length);
  if (body.length === 0) {
    throw new VericertsError(ErrorCodes.INVALID_DID);
  }
  try {
    return base58.decode(body);
  } catch {
    // @scure/base 由来の例外は入力を含み得るため cause を渡さず正規化する。
    throw new VericertsError(ErrorCodes.INVALID_DID);
  }
}
