/**
 * OID4VP 応答暗号化（`direct_post.jwt`）の内部バレル。
 *
 * - ecdh.ts:                ECDH-ES 鍵合意（P-256）と Concat KDF。
 * - jwe.ts:                 JWE Compact Serialization の暗号化プリミティブ（AES-GCM / AES-KW）。
 * - response-encryption.ts: `client_metadata` からの暗号化パラメータ解決と `response` 値の構築。
 */

export {
  encryptJweCompact,
  JWE_ALG_ECDH_ES,
  JWE_ALG_ECDH_ES_A256KW,
  JWE_ENC_A256GCM,
  type JweAlg,
  type JweEnc,
  type JweEncryptParams,
  SUPPORTED_JWE_ALGS,
  SUPPORTED_JWE_ENCS,
} from './jwe.js';
export {
  buildEncryptedResponse,
  type ClientMetadata,
  type EncryptedResponsePayload,
  type ResponseEncryptionParams,
  resolveResponseEncryption,
} from './response-encryption.js';
