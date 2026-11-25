/**
 * Transaction Data 同意イベントの Dashboard ログ記録。
 *
 * Dashboard ログの永続化・署名・Merkle chain は `gdpr` の `DashboardLog` が担う。本モジュールは
 * `transactionDataConsent` エントリ用の payload を組み立て、`DashboardLog.append` へ委譲する薄い
 * アダプタに徹する（署名鍵は `CredentialSigner` で DI し、生 privateKey を露出しない）。
 *
 * セキュリティ / プライバシー上の注意:
 * - ログ payload に Transaction Data 本文（金額・相手方等の `claims`）を含めない。種別（`type`）と
 *   `transaction_data_hashes` のみを記録し、内容は KB-JWT / VP 側に留める（監査には hash で十分）。
 */

import type { CredentialSigner } from '../../credential/vc/signer.js';
import type { DashboardLog } from '../../gdpr/dashboard-log/dashboard-log.js';
import type { DashboardLogEntry } from '../../gdpr/types.js';
import { computeTransactionDataHashes } from './hashes.js';
import {
  TRANSACTION_DATA_HASH_ALG,
  type TransactionDataConsentPayload,
  type TransactionDataEntry,
} from './types.js';

/** `recordTransactionDataConsent` の入力。 */
export interface TransactionDataConsentInput {
  /** 提示先 Verifier 識別子（`client_id` / audience）。 */
  readonly clientId: string;
  /** Authorization Request の `nonce`。 */
  readonly nonce: string;
  /** 同意された Transaction Data（`extractTransactionData` の戻り値）。 */
  readonly transactionData: readonly TransactionDataEntry[];
}

/** Dashboard ログの `transactionDataConsent` エントリ種別。 */
export const TRANSACTION_DATA_CONSENT_LOG_TYPE = 'transactionDataConsent' as const;

/**
 * Transaction Data 同意 payload を組み立てる（内容は含めず種別 + hash のみ）。
 *
 * @param input clientId / nonce / transactionData。
 * @returns 署名対象の `TransactionDataConsentPayload`。
 */
export function buildTransactionDataConsentPayload(
  input: TransactionDataConsentInput,
): TransactionDataConsentPayload {
  return {
    clientId: input.clientId,
    nonce: input.nonce,
    transactionDataTypes: input.transactionData.map((entry) => entry.type),
    transactionDataHashes: computeTransactionDataHashes(input.transactionData),
    hashAlgorithm: TRANSACTION_DATA_HASH_ALG,
  };
}

/**
 * Transaction Data 同意イベントを Dashboard ログに署名済みレコードとして記録する。
 *
 * `DashboardLog.append` に `transactionDataConsent` エントリを委譲する。payload には種別と
 * `transaction_data_hashes` のみを記録し、Transaction Data 本文は含めない（データ最小化）。
 *
 * @param log 記録先の `DashboardLog`。
 * @param input clientId / nonce / transactionData。
 * @param signer Dashboard ログエントリの JWS 署名鍵（`CredentialSigner`）。
 * @returns 追記された署名済みエントリ。
 * @throws 署名演算が失敗した場合（VericertsError、code `1020`）。
 */
export function recordTransactionDataConsent(
  log: DashboardLog,
  input: TransactionDataConsentInput,
  signer: CredentialSigner,
): Promise<DashboardLogEntry> {
  const payload = buildTransactionDataConsentPayload(input);
  // interface はインデックスシグネチャを持たず `Record<string, unknown>` に直接代入できないため、
  // シリアライズ可能な payload を append の型へ橋渡しする（`{ ...payload }` で型を平坦化）。
  return log.append(TRANSACTION_DATA_CONSENT_LOG_TYPE, { ...payload }, signer);
}
