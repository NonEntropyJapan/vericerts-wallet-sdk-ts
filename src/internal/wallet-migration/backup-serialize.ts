/**
 * バックアップコンテナの CBOR / JWE Compact シリアライズ。
 *
 * JSON（`wallet-backup-*.json`）は `JSON.stringify`
 * で足りるため SDK では扱わず、本ファイルは残る 2 形式だけを担当する。
 *
 * - **CBOR**（`*.cbor`、モバイルアドオン向け）: `cbor-x` で `WalletBackup` をそのまま符号化する。
 *   相互運用のため records 拡張を無効化し、map 長は最小長符号化にする。
 * - **JWE Compact**（`*.jwe`、1 受信者向け W2W-Transfer）: RFC 7516 §7.1。本文の対称鍵は
 *   `deriveContainerKey` が導出済みのため、この層では鍵合意を行わず `alg: "dir"` + `enc: "A256GCM"`
 *   固定とする。protected header に載せる `kdf` / `kdfParams` / `recipientKey`（`.json` 形式でも
 *   平文で同梱される非秘密メタ）だけで、インポート側はヘッダから同じ鍵を再導出できる。Concat KDF
 *   を使う `auth/jwe/`（RFC 7518 §4.6.2。OID4VP 応答暗号化専用）は本ファイルからは import しない。
 *
 * セキュリティ上の注意:
 * - 鍵・平文を例外メッセージ・context・cause に含めない。IV は毎回ランダム生成する。
 * - 外部入力（CBOR バイト列 / JWE 文字列）の復号結果は `Object.prototype` を継承しない
 *   オブジェクトへ正規化する（`parse-json.ts` と同じ防御）。
 */

import { base64urlnopad } from '@scure/base';
import { Encoder } from 'cbor-x';
import { isPlainObject } from '../credential/object-guards.js';
import { ErrorCodes, VericertsError } from '../errors.js';
import { decryptAesGcm, encryptAesGcm } from '../keymanager/encryption.js';
import { ownProperty } from '../prototype-safety/own-property.js';
import { parseJsonWithoutPrototype } from '../prototype-safety/parse-json.js';
import { GCM_TAG_LENGTH } from './backup-entry.js';
import { decodeBoundedCbor } from './cbor/bounded-cbor-decode.js';
import {
  BACKUP_CONTENT_ALG,
  type BackupKdfParams,
  type EncryptionHeader,
  type JWK,
  type WalletBackup,
} from './types.js';

/**
 * 相互運用用の CBOR エンコーダ。`useRecords: false` は cbor-x 独自の record 拡張タグを出さず
 * （他実装でも読める素の CBOR）、`variableMapSize: true` は map 長を最小長で符号化する。
 */
const cborEncoder = new Encoder({ useRecords: false, variableMapSize: true });

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

/** JWE Compact のセグメント数（RFC 7516 §7.1）。 */
const JWE_SEGMENT_COUNT = 5;

/**
 * 外部入力から復元した値を `WalletBackup` として受理してよいか検査する。
 *
 * 個々のフィールドの正当性（署名・バージョン・復号可否）は `importBackup` が担うため、ここでは
 * 「後段が前提にする形」だけを確認する。
 *
 * @param value 復元済みの値（プロトタイプ汚染対策済みであること）。
 * @returns `WalletBackup` とみなせる値。
 * @throws 形が異なる場合（VericertsError、code `4033`）。
 */
function toWalletBackup(value: unknown): WalletBackup {
  if (!isPlainObject(value)) {
    throw new VericertsError(ErrorCodes.W2W_INTEGRITY_BROKEN);
  }
  const { version, encryption, credentials, personas, dids, settings, integrity } = value;
  if (
    typeof version !== 'string' ||
    !isPlainObject(encryption) ||
    !isPlainObject(settings) ||
    !isPlainObject(integrity) ||
    !Array.isArray(credentials) ||
    !Array.isArray(personas) ||
    !Array.isArray(dids)
  ) {
    throw new VericertsError(ErrorCodes.W2W_INTEGRITY_BROKEN);
  }
  return value as unknown as WalletBackup;
}

/**
 * バックアップコンテナを CBOR バイト列へ直列化する（`wallet-backup-*.cbor`）。扱えるのは
 * **JSON で表現できる CBOR 値だけ**である（理由は `deserializeBackupFromCbor` を参照）。
 *
 * @param backup 直列化するバックアップ。
 * @returns CBOR バイト列。
 * @throws 符号化に失敗した場合（VericertsError、code `4033`）。
 */
export function serializeBackupToCbor(backup: WalletBackup): Uint8Array {
  try {
    // cbor-x は内部バッファを再利用しうる Buffer を返すため、独立した Uint8Array へ複写する。
    return Uint8Array.from(cborEncoder.encode(backup));
  } catch {
    throw new VericertsError(ErrorCodes.W2W_INTEGRITY_BROKEN);
  }
}

/**
 * CBOR バイト列からバックアップコンテナを復元する。
 *
 * 復元は `cbor-x` も JSON 往復も使わず、`decodeBoundedCbor` が **1 回の走査で検査と復元を同時に行う**
 * 入力長・総ノード数・入れ子深さの仕事量予算を値の確保前に消費し、超過は
 * 何も確保せず拒否する。byte string・tag（共有参照 28/29 を含む）・不定長・非 text キー・不正な UTF-8・
 * NaN / Infinity・末尾の余剰バイトも拒否する（`WalletBackup` は JSON で表現できる値だけ）。
 *
 * CBOR の map キーは攻撃者が任意に選べるため、復元結果の map は `Object.prototype` を継承しない
 * オブジェクトとして直接組み立てる（`__proto__` も通常の own プロパティになる）。
 *
 * 別実装が `ciphertext` / `salt` を byte string・タグ付き値で表現したコンテナは `4033` で拒否される。
 * 意図した制約である（受理するなら `decodeBoundedCbor` に型ごとの予算を足すこと）。
 *
 * @param bytes CBOR バイト列。
 * @returns 復元されたバックアップ（入れ子もプロトタイプなし）。
 * @throws CBOR として解釈できない / 予算超過 / 形が `WalletBackup` でない場合
 *   （VericertsError、code `4033`）。
 */
export function deserializeBackupFromCbor(bytes: Uint8Array): WalletBackup {
  let decoded: unknown;
  try {
    decoded = decodeBoundedCbor(bytes);
  } catch {
    // 復号対象のバイト列は例外に含めない。
    throw new VericertsError(ErrorCodes.W2W_INTEGRITY_BROKEN);
  }
  return toWalletBackup(decoded);
}

/** JWE protected header（`alg: "dir"` 固定）を組み立てる。 */
function buildProtectedHeader(encryption: EncryptionHeader): string {
  const recipientKey = ownProperty<string>(encryption, 'recipientKey');
  const header = {
    alg: 'dir',
    enc: BACKUP_CONTENT_ALG,
    kdf: ownProperty<EncryptionHeader['kdf']>(encryption, 'kdf'),
    kdfParams: ownProperty<BackupKdfParams>(encryption, 'kdfParams'),
    ...(recipientKey !== undefined ? { recipientKey } : {}),
  };
  return base64urlnopad.encode(textEncoder.encode(JSON.stringify(header)));
}

/**
 * バックアップコンテナを JWE Compact Serialization へ暗号化する（`wallet-backup-*.jwe`）。
 *
 * `key` は `exportBackup` が導出済みの本文鍵（PBKDF2 / HKDF のどちらでもよい）。本関数は
 * パスフレーズも `recipientKey` も解釈しない純粋な形式変換である。
 *
 * @param backup 直列化するバックアップ。`encryption` の `kdf` / `kdfParams` / `recipientKey` は
 *   protected header にも複写し、インポート側がヘッダだけから鍵を再導出できるようにする。
 * @param key 本文の 256bit 対称鍵。
 * @returns `protected..iv.ciphertext.tag` 形式の JWE Compact 文字列。
 * @throws 暗号化に失敗した場合（VericertsError、code `1051`）。
 */
export async function serializeBackupToJweCompact(
  backup: WalletBackup,
  key: Uint8Array,
): Promise<string> {
  const protectedHeader = buildProtectedHeader(
    ownProperty<EncryptionHeader>(backup, 'encryption') as EncryptionHeader,
  );
  // RFC 7516 §5.1 手順 14: AAD は protected header の ASCII 表現。IV は毎回ランダム。
  const { iv, ciphertext } = await encryptAesGcm(
    key,
    textEncoder.encode(JSON.stringify(backup)),
    textEncoder.encode(protectedHeader),
  );
  // Web Crypto は「暗号文 || 16 バイトタグ」を返す。JWE Compact は両者を別セグメントで送る。
  const split = ciphertext.length - GCM_TAG_LENGTH;
  return [
    protectedHeader,
    // `alg: "dir"` では encrypted key セグメントは空（RFC 7516 §5.1 手順 6）。
    '',
    base64urlnopad.encode(iv),
    base64urlnopad.encode(ciphertext.subarray(0, split)),
    base64urlnopad.encode(ciphertext.subarray(split)),
  ].join('.');
}

/** JWE Compact を 5 セグメントへ分解する。段数不正は 4033。 */
function splitJweCompact(jwe: string): string[] {
  const segments = jwe.split('.');
  if (segments.length !== JWE_SEGMENT_COUNT) {
    throw new VericertsError(ErrorCodes.W2W_INTEGRITY_BROKEN);
  }
  return segments;
}

/**
 * JWE Compact の protected header を読み、鍵導出に必要な `EncryptionHeader` へ変換する。
 *
 * 本文の復号には先に鍵が要るため、復号前に読めるヘッダ（非秘密メタ）だけを取り出す。ここで得た値は
 * **まだ完全性検証を経ていない**（保証は本文の GCM タグ検証と復元後の ES256 署名検証が与える）。
 * 攻撃者が選べる値として検査する必要があるのはこのためである（`alg` / `enc` / `kdf` / `kdfParams`）。
 *
 * @param jwe JWE Compact 文字列。
 * @returns `deriveContainerKey` に渡す暗号ヘッダ。
 * @throws セグメント数 / base64url / JSON / `alg`・`enc`・`kdf`・`kdfParams` が不正な場合
 *   （VericertsError、code `4033`）。
 */
export function readJweProtectedEncryption(jwe: string): EncryptionHeader {
  const [protectedSegment] = splitJweCompact(jwe);
  let header: unknown;
  try {
    header = parseJsonWithoutPrototype(
      textDecoder.decode(base64urlnopad.decode(protectedSegment ?? '')),
    );
  } catch {
    throw new VericertsError(ErrorCodes.W2W_INTEGRITY_BROKEN);
  }
  if (!isPlainObject(header)) {
    throw new VericertsError(ErrorCodes.W2W_INTEGRITY_BROKEN);
  }
  const { alg, enc, kdf, kdfParams, recipientKey } = header;
  // RFC 7516 §4.1.1 / §4.1.2: 未対応の `alg` / `enc` は解釈せず拒否する（見ないと形式不正が
  // 後段の GCM タグ失敗 4032 に化ける）。本モジュールが出すのは `dir` + `A256GCM` のみ。
  if (alg !== 'dir' || enc !== BACKUP_CONTENT_ALG) {
    throw new VericertsError(ErrorCodes.W2W_INTEGRITY_BROKEN);
  }
  // 未知の `kdf` は、既定値にフォールバックせず壊れたコンテナとして弾く。
  if (kdf !== 'HKDF-SHA-256' && kdf !== 'PBKDF2-SHA-256') {
    throw new VericertsError(ErrorCodes.W2W_INTEGRITY_BROKEN);
  }
  if (!isPlainObject(kdfParams) || typeof kdfParams.salt !== 'string') {
    throw new VericertsError(ErrorCodes.W2W_INTEGRITY_BROKEN);
  }
  return {
    alg: BACKUP_CONTENT_ALG,
    kdf,
    // `epk` の形は `deriveContainerKey` が改めて検査する（own 限定 + オブジェクト判定）。
    kdfParams: kdfParams as unknown as BackupKdfParams,
    ...(isPlainObject(recipientKey) ? { recipientKey: recipientKey as unknown as JWK } : {}),
  };
}

/**
 * JWE Compact からバックアップコンテナを復号・復元する。
 *
 * @param jwe JWE Compact 文字列。
 * @param key 本文の 256bit 対称鍵（`deriveContainerKey` の結果）。
 * @returns 復元されたバックアップ（入れ子もプロトタイプなし）。
 * @throws セグメント / base64url / JSON / 形が不正な場合（VericertsError、code `4033`）、
 *         GCM タグ検証に失敗した場合（VericertsError、code `4032`）。
 */
export async function deserializeBackupFromJweCompact(
  jwe: string,
  key: Uint8Array,
): Promise<WalletBackup> {
  const [protectedSegment, , ivSegment, ciphertextSegment, tagSegment] = splitJweCompact(jwe);
  let iv: Uint8Array;
  let sealed: Uint8Array;
  try {
    iv = base64urlnopad.decode(ivSegment ?? '');
    const ciphertext = base64urlnopad.decode(ciphertextSegment ?? '');
    const tag = base64urlnopad.decode(tagSegment ?? '');
    // Web Crypto は「暗号文 || タグ」を 1 本のバイト列として受ける。
    sealed = new Uint8Array(ciphertext.length + tag.length);
    sealed.set(ciphertext);
    sealed.set(tag, ciphertext.length);
  } catch {
    throw new VericertsError(ErrorCodes.W2W_INTEGRITY_BROKEN);
  }

  let plaintext: Uint8Array;
  try {
    plaintext = await decryptAesGcm(key, iv, sealed, textEncoder.encode(protectedSegment ?? ''));
  } catch {
    // タグ不一致 = 鍵誤り or 改ざん。`decryptEntry` と同じ 4032 に正規化し cause は渡さない。
    throw new VericertsError(ErrorCodes.W2W_PASSPHRASE_WRONG);
  }

  let restored: unknown;
  try {
    restored = parseJsonWithoutPrototype(textDecoder.decode(plaintext));
  } catch {
    throw new VericertsError(ErrorCodes.W2W_INTEGRITY_BROKEN);
  }
  return toWalletBackup(restored);
}
