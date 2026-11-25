/**
 * did:peer numalgo 2 の鍵エレメント（`V` / `E`）の検証（multicodec 接頭辞・鍵の種類・鍵の長さ）。
 *
 * - `V`（署名鍵）は Ed25519 / secp256k1 / P-256 のみ。
 * - `E`（暗号鍵）は鍵合意に使える P-256 / X25519 のみ（Ed25519 / secp256k1 は不可）。
 *
 * 判定は did:key（`method-key.ts`）と同様に、既知 codec を `encodeMulticodecVarint` で再エンコードした
 * canonical prefix との完全一致で行う。非 canonical varint・未知 codec・鍵長不一致は `2001`。
 * 曲線上の点としての妥当性は検査しない（接頭辞と長さのみ）。
 *
 * セキュリティ上の注意: 例外メッセージ・`context` に鍵バイトなどの入力データを含めない。
 */

import { ErrorCodes, VericertsError } from '../../errors.js';
import { encodeMulticodecVarint, multibaseBase58Decode } from '../multibase.js';

/** numalgo 2 の鍵エレメント用途（`V` = 署名鍵 / `E` = 暗号鍵）。 */
export type Numalgo2KeyPurpose = 'V' | 'E';

interface KeySpec {
  /** canonical な multicodec varint prefix。 */
  readonly prefix: Uint8Array;
  /** raw 公開鍵長（バイト）。 */
  readonly length: number;
}

const ED25519: KeySpec = { prefix: encodeMulticodecVarint(0xed), length: 32 };
const SECP256K1: KeySpec = { prefix: encodeMulticodecVarint(0xe7), length: 33 };
const P256: KeySpec = { prefix: encodeMulticodecVarint(0x1200), length: 33 };
const X25519: KeySpec = { prefix: encodeMulticodecVarint(0xec), length: 32 };

/** 用途ごとに許可する鍵の種類。 */
const ALLOWED_KEYS: Readonly<Record<Numalgo2KeyPurpose, readonly KeySpec[]>> = {
  V: [ED25519, SECP256K1, P256],
  E: [P256, X25519],
};

/**
 * numalgo 2 の鍵エレメント値（multibase base58btc）を検証する。
 *
 * @param multibaseKey `V` / `E` エレメントの値（`z...`）。
 * @param purpose 鍵エレメントの用途。
 * @throws multibase 不正・用途に許可されない multicodec・鍵長不一致の場合（VericertsError、code `2001`）。
 */
export function assertNumalgo2Key(multibaseKey: string, purpose: Numalgo2KeyPurpose): void {
  const decoded = multibaseBase58Decode(multibaseKey);
  const matched = ALLOWED_KEYS[purpose].some(
    ({ prefix, length }) =>
      decoded.length === prefix.length + length && prefix.every((byte, i) => decoded[i] === byte),
  );
  if (!matched) {
    throw new VericertsError(ErrorCodes.INVALID_DID);
  }
}
