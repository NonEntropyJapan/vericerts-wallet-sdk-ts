/**
 * W2W バックアップの「1 エントリ」単位の AES-256-GCM 暗号化・復号（`EncryptedCredential` 等）。
 *
 * `exportBackup` / `importBackup` の双方が同じ AAD
 * 組み立て（`kind:id`）を使う必要があるため（食い違うとタグ検証に失敗する）単一ソース化している。
 *
 * セキュリティ上の注意:
 * - 平文・鍵は例外メッセージ・context・cause に含めない。
 * - GCM タグ不一致（= パスフレーズ誤り or 改ざん）は 4032 に正規化する。
 */

import { base64urlnopad } from '@scure/base';
import { ErrorCodes, VericertsError } from '../errors.js';
import { decryptAesGcm, encryptAesGcm } from '../keymanager/encryption.js';
import { ownProperty } from '../prototype-safety/own-property.js';
import type { BackupSourceItem, EncryptedEntry } from './types.js';

/** GCM 認証タグ長（バイト）。encryption.ts の TAG_LENGTH_BITS=128 と一致（16 バイト）。 */
export const GCM_TAG_LENGTH = 16;

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

/** エントリ暗号化時の AAD。ID と kind をバインドし、取り違え・改ざんを検出する。 */
function entryAad(id: string, kind: EncryptedEntry['kind']): Uint8Array {
  return textEncoder.encode(`${kind}:${id}`);
}

/**
 * 平文アイテムを 1 件暗号化して `EncryptedEntry` にする。
 *
 * @param key 導出済み 256bit 鍵。
 * @param kind エントリ種別。
 * @param id エントリ ID。
 * @param data 平文（文字列）。
 * @param format VC フォーマット（任意）。
 * @returns 暗号化エントリ。
 */
export async function encryptEntry(
  key: Uint8Array,
  kind: EncryptedEntry['kind'],
  id: string,
  data: string,
  format?: string,
): Promise<EncryptedEntry> {
  const { iv, ciphertext } = await encryptAesGcm(key, textEncoder.encode(data), entryAad(id, kind));
  const base: EncryptedEntry = {
    id,
    kind,
    ciphertext: base64urlnopad.encode(ciphertext),
    iv: base64urlnopad.encode(iv),
    tag: GCM_TAG_LENGTH,
  };
  return format !== undefined ? { ...base, format } : base;
}

/**
 * 暗号化エントリを復号して平文アイテムに戻す。
 *
 * @param key 導出済み 256bit 鍵。
 * @param entry 暗号化エントリ。
 * @returns 復号済み平文アイテム。
 * @throws パスフレーズ誤り・改ざん時（VericertsError、code `4032`）。
 */
export async function decryptEntry(
  key: Uint8Array,
  entry: EncryptedEntry,
): Promise<BackupSourceItem> {
  let iv: Uint8Array;
  let ct: Uint8Array;
  // エントリのメンバは own 限定で読む。
  const id = ownProperty<string>(entry, 'id') as string;
  const kind = ownProperty<EncryptedEntry['kind']>(entry, 'kind') as EncryptedEntry['kind'];
  try {
    iv = base64urlnopad.decode(ownProperty<string>(entry, 'iv') as string);
    ct = base64urlnopad.decode(ownProperty<string>(entry, 'ciphertext') as string);
  } catch {
    // base64url 不正はコンテナ改ざん相当。パスフレーズ復号失敗として正規化する。
    throw new VericertsError(ErrorCodes.W2W_PASSPHRASE_WRONG);
  }
  let plaintext: Uint8Array;
  try {
    plaintext = await decryptAesGcm(key, iv, ct, entryAad(id, kind));
  } catch {
    // GCM タグ不一致 = パスフレーズ誤り or 改ざん。秘密は cause に含めない。
    throw new VericertsError(ErrorCodes.W2W_PASSPHRASE_WRONG);
  }
  const item: BackupSourceItem = { id, data: textDecoder.decode(plaintext) };
  const format = ownProperty<string>(entry, 'format');
  return format !== undefined ? { ...item, format } : item;
}
