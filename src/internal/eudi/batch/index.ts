/**
 * EUDI Batch Credential プールの操作。
 *
 * Batch Issuance 要求、未使用 VC の選択・消費、補充の判断、プールの集約メタデータを提供する。
 */

export { consumeCredential, countAvailable, purgeExpired } from './pool.js';
export { BatchCredentialPoolStore } from './pool-store.js';
export { evaluateRefill } from './refill.js';
export { buildBatchCredentialRequest } from './request.js';
export {
  BATCH_DEFAULTS,
  type BatchCredentialPool,
  type BatchCredentialRequest,
  type BatchPoolItem,
  type BatchProof,
  type ConsumeResult,
  type CreateBatchCredentialPoolOptions,
  type PurgeResult,
  type RefillConfig,
  type RefillDecision,
  type RefillInput,
} from './types.js';
