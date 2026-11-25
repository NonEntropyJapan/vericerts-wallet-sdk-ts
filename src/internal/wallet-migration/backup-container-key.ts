/**
 * バックアップコンテナ本文の対称鍵の決定（エクスポート側）と再導出（インポート側）。
 * `PBKDF2-SHA-256` / `HKDF-SHA-256` の分岐を単一ソース化する。
 *
 * エクスポート側（`buildEncryption`）とインポート側（`deriveContainerKey`）は対であり、後者は
 * `importBackup`（JSON）と `importBackupFromJweCompact`（JWE Compact）の双方から呼ばれる。片方
 * だけが更新されて乖離する（= 一方は `recipientKey` を無視して復号できる）のを避けるため集約した。
 *
 * セキュリティ上の注意:
 * - パスフレーズ・受信者秘密鍵・導出鍵は例外メッセージ・context・cause に一切含めない。
 * - 「コンテナの構造が壊れている / 改ざんされている」は 4033、「復号に必要な秘密を呼び出し側が
 *   持っていない」は 4032 に正規化する（`decryptEntry` のパスフレーズ誤りと同じバケツ）。
 */

import { base64urlnopad } from '@scure/base';
import { ErrorCodes, VericertsError } from '../errors.js';
import { deriveKey } from '../keymanager/kdf.js';
import { ownProperty } from '../prototype-safety/own-property.js';
import { deriveEcdhKeyForRecipient, deriveEcdhKeyFromEphemeral } from './kdf/backup-ecdh.js';
import {
  DEFAULT_PBKDF2_ITERATIONS,
  isValidPbkdf2Iterations,
  pbkdf2Params,
} from './kdf/backup-kdf.js';
import {
  BACKUP_CONTENT_ALG,
  type BackupKdfParams,
  type EncryptionHeader,
  type ExportOptions,
  type JWK,
} from './types.js';

/** エクスポート時に決まった暗号ヘッダと、それに対応する本文鍵。 */
export interface ContainerEncryption {
  readonly encryption: EncryptionHeader;
  readonly key: Uint8Array;
}

/**
 * エクスポート時の暗号ヘッダと本文鍵を決める（`EncryptionHeader`）。
 *
 * `recipientKey` 指定時は鍵導出そのものを ECDH-ES + HKDF-SHA-256 に切り替える。`iterations`
 * は PBKDF2 専用のため HKDF 側の `kdfParams` には載せない。
 *
 * @param opts エクスポートオプション（外部入力。任意プロパティは own 限定で読む）。
 * @param passphrase 検証済みのパスフレーズ（PBKDF2 分岐でのみ使用）。
 * @param salt 生成済みのランダム salt（両分岐で共有する）。
 * @returns 暗号ヘッダと本文鍵。
 * @throws `recipientKey` の形式が不正 / 鍵合意に失敗した場合、`iterations` が範囲外の場合
 *         （VericertsError、code `1051`）。
 */
export async function buildEncryption(
  opts: ExportOptions,
  passphrase: string,
  salt: Uint8Array,
): Promise<ContainerEncryption> {
  const recipientKey = ownProperty<ExportOptions['recipientKey']>(opts, 'recipientKey');
  if (recipientKey !== undefined) {
    const { key, epk } = deriveEcdhKeyForRecipient(recipientKey, salt);
    const encryption: EncryptionHeader = {
      alg: BACKUP_CONTENT_ALG,
      kdf: 'HKDF-SHA-256',
      kdfParams: { salt: base64urlnopad.encode(salt), epk },
      recipientKey,
      // 本文鍵は受信者鍵由来であり、パスフレーズでは開けない。
      passphraseProtected: false,
    };
    return { key, encryption };
  }
  // 任意プロパティは own 限定で読む（継承した `iterations` は KDF 反復回数を弱める）。
  const iterations = ownProperty<number>(opts, 'iterations') ?? DEFAULT_PBKDF2_ITERATIONS;
  // インポート側と同じ範囲検査をここでも行う。範囲外を素通しすると、非整数なら自 SDK の
  // `importBackup` が必ず 4033 で弾く「開けないコンテナ」が、下限未満なら極端に弱いコンテナが
  // 黙って生成される。
  if (!isValidPbkdf2Iterations(iterations)) {
    throw new VericertsError(ErrorCodes.ENCRYPT_FAILED);
  }
  const key = await deriveKey(pbkdf2Params(iterations), passphrase, salt);
  const encryption: EncryptionHeader = {
    alg: BACKUP_CONTENT_ALG,
    kdf: 'PBKDF2-SHA-256',
    kdfParams: { iterations, salt: base64urlnopad.encode(salt) },
    passphraseProtected: true,
  };
  return { key, encryption };
}

/**
 * `EncryptionHeader` と呼び出し側の秘密素材から、コンテナ本文の 256bit 対称鍵を再導出する。
 *
 * - `kdf: 'PBKDF2-SHA-256'`: `passphrase` + `kdfParams.salt` から導出する（Wallet Swap）。
 * - `kdf: 'HKDF-SHA-256'`: `recipientPrivateKey` + `kdfParams.epk` + `kdfParams.salt` から
 *   ECDH-ES 共有秘密を再現して導出する（W2W-Transfer）。この分岐で `passphrase` は使わないが、
 *   呼び出し時の引数としては両 KDF で必須。
 *
 * @param encryption コンテナの暗号ヘッダ（外部入力。own 限定で読む）。
 * @param passphrase エクスポート時と同一のパスフレーズ（PBKDF2 分岐でのみ使用）。
 * @param recipientPrivateKey `recipientKey` に対応する P-256 秘密鍵（HKDF 分岐で必須）。
 * @returns コンテナ本文の対称鍵（32 バイト）。
 * @throws `kdf` 未対応 / `salt`・`epk`・`iterations` が不正な場合（VericertsError、code `4033`）、
 *         HKDF 分岐で `recipientPrivateKey` が未指定の場合（VericertsError、code `4032`）。
 */
export async function deriveContainerKey(
  encryption: EncryptionHeader,
  passphrase: string,
  recipientPrivateKey?: Uint8Array,
): Promise<Uint8Array> {
  // ヘッダのメンバは own 限定で読む。省略した `kdf` / `kdfParams` が汚染値を拾って鍵導出の分岐を選ばせない。
  const kdf = ownProperty<EncryptionHeader['kdf']>(encryption, 'kdf');
  const kdfParams = ownProperty<BackupKdfParams>(encryption, 'kdfParams');
  if (typeof kdfParams !== 'object' || kdfParams === null) {
    throw new VericertsError(ErrorCodes.W2W_INTEGRITY_BROKEN);
  }
  let salt: Uint8Array;
  try {
    salt = base64urlnopad.decode(ownProperty<string>(kdfParams, 'salt') as string);
  } catch {
    throw new VericertsError(ErrorCodes.W2W_INTEGRITY_BROKEN);
  }

  if (kdf === 'HKDF-SHA-256') {
    // `epk` はコンテナの構造の一部。欠落・非オブジェクトは salt 不正と同じ「壊れたコンテナ」。
    const epk = ownProperty<JWK>(kdfParams, 'epk');
    if (typeof epk !== 'object' || epk === null) {
      throw new VericertsError(ErrorCodes.W2W_INTEGRITY_BROKEN);
    }
    if (recipientPrivateKey === undefined) {
      // 受信者秘密鍵を持たない呼び出し側は復号できない（パスフレーズだけでは開けない）。
      throw new VericertsError(ErrorCodes.W2W_PASSPHRASE_WRONG);
    }
    try {
      return deriveEcdhKeyFromEphemeral(recipientPrivateKey, epk, salt);
    } catch {
      // オブジェクト形状でも中身が壊れた `epk`（`{}` / 非対応 crv / 曲線外の点 / 非 base64url）は
      // 鍵合意層では 1050 になる。公開 API の契約は「壊れたコンテナ = 4033」なので正規化する。
      throw new VericertsError(ErrorCodes.W2W_INTEGRITY_BROKEN);
    }
  }

  if (kdf !== 'PBKDF2-SHA-256') {
    // 未知の KDF は既定へフォールバックせず fail-closed にする。
    throw new VericertsError(ErrorCodes.W2W_INTEGRITY_BROKEN);
  }
  // コンテナは外部入力。反復回数を持たないコンテナが汚染値で鍵導出されるのを防ぐ。
  // 既定値へのフォールバックは「キーが無い」場合だけで、`null` 等の値は壊れた値として扱う。
  const raw = ownProperty<number>(kdfParams, 'iterations');
  const iterations = raw === undefined ? DEFAULT_PBKDF2_ITERATIONS : raw;
  // JWE 経路は署名検証前にこの値で鍵導出するため攻撃者が選べる。非整数・範囲外は PBKDF2 に
  // 渡さず「壊れたコンテナ」として即座に弾く（DoS 対策）。
  if (!isValidPbkdf2Iterations(iterations)) {
    throw new VericertsError(ErrorCodes.W2W_INTEGRITY_BROKEN);
  }
  return deriveKey(pbkdf2Params(iterations), passphrase, salt);
}
