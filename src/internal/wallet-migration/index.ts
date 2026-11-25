/**
 * Wallet-to-Wallet（W2W）Migration モジュールの公開エントリ。
 *
 * バックアップ、デバイス移行、一時共有、および各機能で使用する型を再エクスポートする。
 */

export {
  exportBackup,
  exportBackupAsJweCompact,
  importBackup,
  importBackupFromJweCompact,
} from './backup.js';
export { deserializeBackupFromCbor, serializeBackupToCbor } from './backup-serialize.js';
export {
  createLend,
  type ExpireOverdueLendsDependencies,
  expireOverdueLends,
  type RedeemLendDependencies,
  type RevokeLendDependencies,
  redeemLend,
  revokeLend,
  type ScheduleLendExpiryChecksDependencies,
  scheduleLendExpiryChecks,
  verifyLendSignature,
} from './lend.js';
export {
  type AcceptMigrationDependencies,
  acceptDeviceMigration,
  buildTransferOffer,
  type CompleteMigrationDependencies,
  completeMigration,
  parseInvitation,
  type StartMigrationDependencies,
  startDeviceMigration,
} from './migration.js';
export {
  BACKUP_CONTENT_ALG,
  BACKUP_SIGNATURE_ALG,
  type BackupKdfParams,
  type BackupSigner,
  type BackupSource,
  type BackupSourceItem,
  type CreateLendDependencies,
  DEFAULT_LEND_EXPIRY_CHECK_INTERVAL_MS,
  type EncryptedEntry,
  type EncryptionHeader,
  type ExportOptions,
  type ImportResult,
  type IntegrityProof,
  type JWK,
  type LendToken,
  MIN_PASSPHRASE_LENGTH,
  type MigrationResult,
  type MigrationSession,
  type OOBInvitation,
  type TransferMode,
  type TransferOfferMessage,
  W2W_MESSAGE_TYPES,
  WALLET_BACKUP_VERSION,
  type WalletBackup,
} from './types.js';
export {
  type ForeignCredentialEntry,
  type ForeignWalletBackup,
  type ImportForeignBackupDependencies,
  importForeignBackup,
} from './vendor-import/index.js';
