/**
 * V2 暗号化エンベロープの先頭メタ（AAD）構築・byte 列 pack / unpack の純粋関数。
 *
 * `../kdf.ts` から KDF 導出・直列化と責務を分離し、行数上限（CI 規約: 1 ファイル 300 行以下）に
 * 対応する。`../kdf.ts` は本モジュールを再エクスポートし、公開 API の入口を一本化する。
 * `./envelope-cipher.ts`（AES-GCM 暗号化・復号）は本モジュールへ委譲する。
 *
 * V2 エンベロープ構造:
 * `[version(0x02)] || [kdfJsonLen(2 BE)] || [kdfJson] || [salt(32)] || [iv(12)] || [ciphertext+tag]`。
 *
 * セキュリティ上の注意:
 * - password / 導出鍵などの秘密は本モジュールに渡らない。ct（暗号文+タグ）自体は秘密ではないが、
 *   例外メッセージには含めない。
 */

import { ErrorCodes, VericertsError } from '../../errors.js';
import { type KdfParams, parseKdf } from '../kdf.js';

/** エンベロープの salt 長（32 バイト）。 */
const SALT_LENGTH = 32;
/** GCM IV 長（バイト）。encryption.ts と一致させる。 */
const IV_LENGTH = 12;
/** kdfJson 長を格納するヘッダ長（バイト、2 バイト BE）。 */
const KDF_LEN_HEADER = 2;

/** 2 バイト BE で `value` を `bytes[offset..offset+2]` に書き込む（0..65535 前提）。 */
function writeUint16BE(bytes: Uint8Array, offset: number, value: number): void {
  bytes[offset] = (value >> 8) & 0xff;
  bytes[offset + 1] = value & 0xff;
}

/** 2 バイト BE で `bytes[offset..offset+2]` を読み出す。 */
function readUint16BE(bytes: Uint8Array, offset: number): number {
  return ((bytes[offset] ?? 0) << 8) | (bytes[offset + 1] ?? 0);
}

/** V2 エンベロープのヘッダ最小長（version(1) + kdfJsonLen(2)）。 */
const V2_HEADER_LENGTH = 1 + KDF_LEN_HEADER;
/** V2 エンベロープのバージョンバイト。 */
const ENVELOPE_VERSION_V2 = 0x02;
/** GCM 認証タグ長（バイト）。encryption.ts の TAG_LENGTH_BITS=128 と一致する（128bit = 16 バイト）。 */
const GCM_TAG_LENGTH = 16;

/**
 * V2 エンベロープの先頭メタ（AAD）を組み立てる純粋関数。
 *
 * 構造: `[version(0x02)] || [kdfJsonLen(2 BE)] || [kdfJson]`。`packEnvelopeV2` の先頭メタと同一バイト列で、
 * AES-GCM の AAD としてこの先頭メタをバインドすることで KDF パラメータの改ざんを検出できる。
 *
 * @param kdfJson `serializeKdf` 由来の KDF JSON バイト列。
 * @returns AAD バイト列（先頭メタ）。
 * @throws kdfJson 長が 2 バイト BE 長ヘッダ上限（65535）を超える場合（VericertsError、code `1051`）。
 */
export function buildEnvelopeAad(kdfJson: Uint8Array): Uint8Array {
  // 2 バイト BE 長ヘッダの上限は 65535。超過すると上位ビットが切り捨てられ unpack と不整合になる。
  if (kdfJson.length > 0xffff) {
    throw new VericertsError(ErrorCodes.ENCRYPT_FAILED);
  }
  const aad = new Uint8Array(V2_HEADER_LENGTH + kdfJson.length);
  aad[0] = ENVELOPE_VERSION_V2;
  writeUint16BE(aad, 1, kdfJson.length);
  aad.set(kdfJson, V2_HEADER_LENGTH);
  return aad;
}

/**
 * V2 エンベロープを組み立てる。
 *
 * 構造: `[version(0x02)] || [kdfJsonLen(2 BE)] || [kdfJson] || [salt(32)] || [iv(12)] || [ciphertext+tag]`。
 *
 * @param kdfJson `serializeKdf` 由来の KDF JSON バイト列。
 * @param salt salt（32 バイト）。
 * @param iv GCM IV（12 バイト）。
 * @param ct 暗号文 || GCM タグ。
 * @returns 連結したエンベロープ。
 */
export function packEnvelopeV2(
  kdfJson: Uint8Array,
  salt: Uint8Array,
  iv: Uint8Array,
  ct: Uint8Array,
): Uint8Array {
  // 先頭メタ（version || kdfJsonLen || kdfJson）は AAD と同一バイト列を再利用する（重複生成を避ける）。
  const head = buildEnvelopeAad(kdfJson);
  const envelope = new Uint8Array(head.length + SALT_LENGTH + IV_LENGTH + ct.length);
  envelope.set(head, 0);
  let offset = head.length;
  envelope.set(salt, offset);
  offset += SALT_LENGTH;
  envelope.set(iv, offset);
  offset += IV_LENGTH;
  envelope.set(ct, offset);
  return envelope;
}

/**
 * V2 エンベロープを各要素へ分解し、KDF パラメータを検証する。
 *
 * 認証前 DoS 対策として、ct 長ガード（GCM タグ最小長を満たすか）を `parseKdf`（鍵導出の前提検証）
 * より前に行い、短い偽エンベロープを鍵導出前に弾く。`aad` は先頭メタ（version || kdfJsonLen || kdfJson）
 * の subarray で、GCM の AAD として KDF パラメータをバインドする。
 *
 * @param env `packEnvelopeV2` 由来のエンベロープ（先頭バイトは 0x02 である前提）。
 * @returns 検証済み KDF パラメータと salt / iv / ct / aad。
 * @throws 長さ不足 / ct 長不足 / KDF 不正の場合（VericertsError、code `1050`）。
 */
export function unpackEnvelopeV2(env: Uint8Array): {
  kdf: KdfParams;
  salt: Uint8Array;
  iv: Uint8Array;
  ct: Uint8Array;
  aad: Uint8Array;
} {
  if (env.length < V2_HEADER_LENGTH) {
    throw new VericertsError(ErrorCodes.DECRYPT_FAILED);
  }
  const kdfJsonLen = readUint16BE(env, 1);
  let offset = V2_HEADER_LENGTH;
  // kdfJson + salt + iv + GCM タグ の最小長を満たすか検証する（ct は GCM タグ 16 バイト以上を要求）。
  if (env.length < offset + kdfJsonLen + SALT_LENGTH + IV_LENGTH + GCM_TAG_LENGTH) {
    throw new VericertsError(ErrorCodes.DECRYPT_FAILED);
  }
  const aad = env.subarray(0, V2_HEADER_LENGTH + kdfJsonLen);
  const kdfJson = env.subarray(offset, offset + kdfJsonLen);
  offset += kdfJsonLen;
  const salt = env.subarray(offset, offset + SALT_LENGTH);
  offset += SALT_LENGTH;
  const iv = env.subarray(offset, offset + IV_LENGTH);
  offset += IV_LENGTH;
  const ct = env.subarray(offset);
  // ct 長ガードの後に parseKdf を呼ぶ（巨大 m を伴わない短い偽エンベロープも鍵導出前に弾く）。
  return { kdf: parseKdf(kdfJson), salt, iv, ct, aad };
}
