/**
 * W2W バックアップのエクスポート・インポート。
 *
 * 暗号設計:
 * - 各エントリ（VC / Persona / DID / Settings）は AES-256-GCM で個別に暗号化する
 *   （`backup-entry.ts`。AAD にエントリ ID + kind をバインドし取り違え・改ざんを検出する）。
 * - 対称鍵は `recipientKey` 未指定ならパスフレーズから PBKDF2-SHA-256 で、指定時は受信者鍵との
 *   ECDH-ES 共有秘密から HKDF-SHA-256 で導出する（`backup-ecdh.ts` / `backup-container-key.ts`）。
 * - コンテナ全体（`integrity` を除く）に ES256 detached 署名を付す。
 *
 * セキュリティ上の注意:
 * - パスフレーズ / 平文 / 導出鍵は例外メッセージ・context・cause に含めない。
 * - パスフレーズ復号失敗は 4032、署名検証失敗は 4033、バージョン非対応は 4036 に正規化する。
 */

import { base64urlnopad } from '@scure/base';
import { ErrorCodes, VericertsError } from '../errors.js';
import type { PublicKeyJwk } from '../identity/did.js';
import { ownProperty } from '../prototype-safety/own-property.js';
import { buildEncryption, deriveContainerKey } from './backup-container-key.js';
import { decryptEntry, encryptEntry } from './backup-entry.js';
import { backupDigest, verifyIntegrity } from './backup-integrity.js';
import {
  deserializeBackupFromJweCompact,
  readJweProtectedEncryption,
  serializeBackupToJweCompact,
} from './backup-serialize.js';
import { SALT_LENGTH } from './kdf/backup-kdf.js';
import { isPassphraseStrongEnough } from './passphrase-strength.js';
import {
  BACKUP_SIGNATURE_ALG,
  type BackupSigner,
  type BackupSource,
  type BackupSourceItem,
  type EncryptedEntry,
  type EncryptionHeader,
  type ExportOptions,
  type ImportResult,
  MIN_PASSPHRASE_LENGTH,
  WALLET_BACKUP_VERSION,
  type WalletBackup,
} from './types.js';

/** `buildBackup` の結果。`key` を返すのは同じ鍵を再導出せずに再直列化するため。 */
interface BuiltBackup {
  readonly backup: WalletBackup;
  readonly key: Uint8Array;
}

/**
 * 暗号化 + 署名済みコンテナと、その本文鍵を組み立てる（`exportBackup` の実体）。本文鍵も返すのは、
 * 同じエクスポートを JWE Compact へ直列化する際に PBKDF2（既定 600,000 反復）を再実行しないため。
 *
 * @param source エクスポート対象の Wallet 状態（平文）。
 * @param signer コンテナ全体に ES256 detached 署名を付す署名者。
 * @param opts エクスポートオプション。
 * @returns コンテナと本文鍵。
 * @throws パスフレーズが短いか弱い場合（VericertsError、code `4032`）。
 */
async function buildBackup(
  source: BackupSource,
  signer: BackupSigner,
  opts: ExportOptions,
): Promise<BuiltBackup> {
  // `passphrase` はバックアップ全体の暗号化鍵の素。継承値を拾うと **攻撃者の知る
  // パスフレーズで暗号化**され、長さ/強度ガードも同じ汚染値を見るため素通りする。
  const passphrase = ownProperty<string>(opts, 'passphrase');
  if (
    typeof passphrase !== 'string' ||
    passphrase.length < MIN_PASSPHRASE_LENGTH ||
    !isPassphraseStrongEnough(passphrase)
  ) {
    // 短い/弱い（zxcvbn スコア < 3）パスフレーズは復号失敗と同じ 4032 で拒否する（秘密は含めない）。
    // `recipientKey` 指定時（HKDF 経路）も無条件に適用する: `ExportOptions.passphrase` は必須
    // 項目であり、変わるのは本文鍵の導出元だけで、強いパスフレーズを求める契約は緩めない。
    throw new VericertsError(ErrorCodes.W2W_PASSPHRASE_WRONG);
  }
  const salt = crypto.getRandomValues(new Uint8Array(SALT_LENGTH));
  const { encryption, key } = await buildEncryption(opts, passphrase, salt);

  const excluded = new Set(ownProperty<readonly string[]>(opts, 'excludeFormats') ?? []);
  const includeVCs = ownProperty<boolean>(opts, 'includeVCs') ?? true;
  const includePersonas = ownProperty<boolean>(opts, 'includePersonas') ?? true;

  const credentials: EncryptedEntry[] = [];
  if (includeVCs) {
    for (const vc of source.credentials) {
      // `format` は省略可能。鎖読みすると `Object.prototype.format` の汚染値が除外形式と一致して、`format` を持たない VC が
      // バックアップから黙って欠落する。
      const format = ownProperty<string>(vc, 'format');
      if (format !== undefined && excluded.has(format)) {
        continue;
      }
      credentials.push(await encryptEntry(key, 'credential', vc.id, vc.data, format));
    }
  }

  const personas: EncryptedEntry[] = [];
  if (includePersonas) {
    for (const p of source.personas) {
      personas.push(await encryptEntry(key, 'persona', p.id, p.data));
    }
  }

  const dids: EncryptedEntry[] = [];
  for (const d of source.dids) {
    dids.push(await encryptEntry(key, 'did', d.id, d.data));
  }

  const settings = await encryptEntry(
    key,
    'settings',
    'settings',
    ownProperty<string>(source, 'settings') ?? '{}',
  );

  const walletProvider = ownProperty<string>(source, 'walletProvider');
  const unsigned: Omit<WalletBackup, 'integrity'> = {
    version: WALLET_BACKUP_VERSION,
    createdAt: new Date().toISOString(),
    walletId: source.walletId,
    ...(walletProvider !== undefined ? { walletProvider } : {}),
    encryption,
    credentials,
    personas,
    dids,
    settings,
  };

  const signature = signer.sign(backupDigest(unsigned));
  return {
    key,
    backup: {
      ...unsigned,
      integrity: {
        alg: BACKUP_SIGNATURE_ALG,
        signature: base64urlnopad.encode(signature),
        signerKeyId: signer.keyId,
      },
    },
  };
}

/**
 * Wallet 状態を暗号化 + 署名済みの `WalletBackup` にエクスポートする。
 *
 * パスフレーズは 10 文字以上、かつ zxcvbn スコア 3 以上を要求する。`includeVCs` /
 * `includePersonas` が `false` の場合は該当エントリを空にする。`excludeFormats` に一致する VC は
 * 除外する。`recipientKey` を指定すると本文鍵は ECDH-ES + HKDF-SHA-256 で導出され、対応する
 * 秘密鍵の保有者だけが `importBackup` できる。
 *
 * @param source エクスポート対象の Wallet 状態（平文）。
 * @param signer コンテナ全体に ES256 detached 署名を付す署名者。
 * @param opts エクスポートオプション（パスフレーズ / 包含フラグ / 除外フォーマット等）。
 * @returns 暗号化 + 署名済みバックアップコンテナ。
 * @throws パスフレーズが短いか弱い場合（VericertsError、code `4032`）。
 */
export async function exportBackup(
  source: BackupSource,
  signer: BackupSigner,
  opts: ExportOptions,
): Promise<WalletBackup> {
  return (await buildBackup(source, signer, opts)).backup;
}

/**
 * Wallet 状態をエクスポートし、JWE Compact 形式へ直列化する（`wallet-backup-*.jwe`）。
 *
 * @param source エクスポート対象の Wallet 状態（平文）。
 * @param signer コンテナ全体に ES256 detached 署名を付す署名者。
 * @param opts エクスポートオプション（`exportBackup` と同一）。
 * @returns JWE Compact 文字列。
 * @throws パスフレーズが短いか弱い場合（VericertsError、code `4032`）。
 */
export async function exportBackupAsJweCompact(
  source: BackupSource,
  signer: BackupSigner,
  opts: ExportOptions,
): Promise<string> {
  const { backup, key } = await buildBackup(source, signer, opts);
  return serializeBackupToJweCompact(backup, key);
}

/**
 * バックアップコンテナをインポートし、署名検証 + 復号して Wallet 状態に復元する。
 *
 * 手順:
 * 1. バージョン照合（`1.0` 以外は 4036）。
 * 2. ES256 完全性証明を検証（失敗は 4033）。
 * 3. ヘッダの `kdf` に従って本文鍵を再導出し各エントリを復号（失敗は 4032）。
 *
 * `kdf: 'HKDF-SHA-256'`（`recipientKey` 保護）でも `passphrase` 引数は必須だが、鍵導出には使用しない。
 *
 * @param backup インポート対象のバックアップ。
 * @param passphrase エクスポート時と同一のパスフレーズ（PBKDF2 コンテナで使用）。
 * @param signerPublicKeyJwk 署名者の EC 公開鍵 JWK（完全性検証用）。
 * @param recipientPrivateKey `recipientKey` 保護コンテナを開くための P-256 秘密鍵（32 バイト）。
 * @returns 復元された Wallet 状態と要約。
 * @throws バージョン非対応（4036）/ 署名検証失敗・`epk`・`kdfParams.iterations` 不正（4033）/
 *         パスフレーズ誤り・受信者秘密鍵の欠落や不一致（4032）。`4032` を「パスフレーズが違う」と
 *         決め打ちせず、`backup.encryption.kdf` が `HKDF-SHA-256` なら `recipientPrivateKey` の
 *         欠落・不一致を疑うこと（復号オラクルを作らないため両者を区別しない）。
 */
export async function importBackup(
  backup: WalletBackup,
  passphrase: string,
  signerPublicKeyJwk: PublicKeyJwk,
  recipientPrivateKey?: Uint8Array,
): Promise<ImportResult> {
  // コンテナのメンバは own 限定で読む。手組みの backup が省略したメンバを `Object.prototype` の汚染値で補えない。
  if (ownProperty<unknown>(backup, 'version') !== WALLET_BACKUP_VERSION) {
    throw new VericertsError(ErrorCodes.W2W_INCOMPATIBLE_VERSION);
  }
  if (!verifyIntegrity(backup, signerPublicKeyJwk)) {
    throw new VericertsError(ErrorCodes.W2W_INTEGRITY_BROKEN);
  }

  const entriesOf = (name: 'credentials' | 'personas' | 'dids'): readonly EncryptedEntry[] => {
    const entries = ownProperty<readonly EncryptedEntry[]>(backup, name);
    if (!Array.isArray(entries)) {
      throw new VericertsError(ErrorCodes.W2W_INTEGRITY_BROKEN);
    }
    return entries;
  };
  const encryption = ownProperty<EncryptionHeader>(backup, 'encryption');
  const settings = ownProperty<EncryptedEntry>(backup, 'settings');
  if (encryption === undefined || settings === undefined) {
    throw new VericertsError(ErrorCodes.W2W_INTEGRITY_BROKEN);
  }
  const key = await deriveContainerKey(encryption, passphrase, recipientPrivateKey);

  const credentials: BackupSourceItem[] = [];
  for (const entry of entriesOf('credentials')) {
    credentials.push(await decryptEntry(key, entry));
  }
  const personas: BackupSourceItem[] = [];
  for (const entry of entriesOf('personas')) {
    personas.push(await decryptEntry(key, entry));
  }
  const dids: BackupSourceItem[] = [];
  for (const entry of entriesOf('dids')) {
    dids.push(await decryptEntry(key, entry));
  }
  const settingsItem = await decryptEntry(key, settings);

  // 復元 ID の重複を competition として検出する（種別内で重複した ID）。
  const conflicts = findDuplicateIds([...credentials, ...personas, ...dids]);

  return {
    summary: {
      vcCount: credentials.length,
      personaCount: personas.length,
      didCount: dids.length,
    },
    credentials,
    personas,
    dids,
    settings: settingsItem.data,
    conflicts,
    // 自ベンダーコンテナには対応外フォーマットの VC が入らないため常に空。
    warnings: [],
  };
}

/**
 * JWE Compact 形式のバックアップを復号し、`importBackup` と同じ検証を通して復元する。
 *
 * JWE 本文を開くには先に本文鍵が要るため、protected header（非秘密メタ）から `kdf` /
 * `kdfParams` / `recipientKey` を読んで鍵を導出する。
 *
 * @param jwe `exportBackupAsJweCompact` が生成した JWE Compact 文字列。
 * @param passphrase エクスポート時と同一のパスフレーズ（PBKDF2 コンテナで使用）。
 * @param signerPublicKeyJwk 署名者の EC 公開鍵 JWK（完全性検証用）。
 * @param recipientPrivateKey `recipientKey` 保護コンテナを開くための P-256 秘密鍵（32 バイト）。
 * @returns 復元された Wallet 状態と要約。
 * @throws JWE の形（`alg` / `enc` / `kdf` / `kdfParams` を含む）が不正（4033）/ 復号失敗（4032）の
 *         ほか `importBackup` と同じ例外。`4032` の読み方も `importBackup` と同じで、protected
 *         header の `kdf` が `HKDF-SHA-256` なら `recipientPrivateKey` 側を疑うこと。
 */
export async function importBackupFromJweCompact(
  jwe: string,
  passphrase: string,
  signerPublicKeyJwk: PublicKeyJwk,
  recipientPrivateKey?: Uint8Array,
): Promise<ImportResult> {
  const encryption = readJweProtectedEncryption(jwe);
  const key = await deriveContainerKey(encryption, passphrase, recipientPrivateKey);
  const backup = await deserializeBackupFromJweCompact(jwe, key);
  // `importBackup` 内で同じ鍵をもう一度導出する（KDF 1 回分の重複）。検証手順を 1 か所に保つ方を
  // 優先した意図的なトレードオフである。
  return importBackup(backup, passphrase, signerPublicKeyJwk, recipientPrivateKey);
}

/**
 * 種別横断で重複する ID を検出する（インポート時の競合検知）。
 *
 * @param items 復元済み平文アイテム。
 * @returns 重複した ID の配列（重複なしなら空配列）。
 */
function findDuplicateIds(items: readonly BackupSourceItem[]): string[] {
  const seen = new Set<string>();
  const dups = new Set<string>();
  for (const item of items) {
    if (seen.has(item.id)) {
      dups.add(item.id);
    }
    seen.add(item.id);
  }
  return [...dups];
}
