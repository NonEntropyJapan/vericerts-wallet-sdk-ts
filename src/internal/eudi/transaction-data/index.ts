/**
 * eudi/transaction-data モジュールの公開エントリ。
 *
 * OID4VP Authorization Request からの Transaction Data 抽出・KB-JWT の
 * `transaction_data_hashes` 計算と格納・提示イベントの Dashboard ログ記録
 * ・受領 KB-JWT の `transaction_data_hashes` と要求 Transaction Data の突合
 * （`verify.ts`）を再エクスポートする。facade（`wallet.ts` / `index.ts`）への配線は
 * 統合担当が行う。
 */

export {
  buildTransactionDataConsentPayload,
  recordTransactionDataConsent,
  TRANSACTION_DATA_CONSENT_LOG_TYPE,
  type TransactionDataConsentInput,
} from './consent-log.js';
export { extractTransactionData } from './extract.js';
export {
  addKeyBindingWithTransactionData,
  computeTransactionDataHashes,
  computeTransactionDataHashesWithAlg,
  type TransactionDataKeyBindingOptions,
} from './hashes.js';
export {
  TRANSACTION_DATA_HASH_ALG,
  type TransactionDataConsentPayload,
  type TransactionDataEntry,
} from './types.js';
export {
  type VerifyTransactionDataHashesOptions,
  verifyTransactionDataHashes,
} from './verify.js';
