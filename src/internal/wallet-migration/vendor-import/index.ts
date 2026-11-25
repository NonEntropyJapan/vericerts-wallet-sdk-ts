/**
 * 別ベンダー Wallet Backup コンテナ取り込みのバレル。
 *
 * SDK 独自の受理プロファイルは `container.ts` に定義する。
 */

export type { ForeignCredentialEntry, ForeignWalletBackup } from './container.js';
export { parseForeignWalletBackup } from './container.js';
export {
  type ImportForeignBackupDependencies,
  importForeignBackup,
} from './import-foreign.js';
