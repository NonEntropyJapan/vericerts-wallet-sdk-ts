/**
 * 用途別 entry `@vericerts/vericerts-wallet-sdk/common`。
 *
 * - サブパス専用バレル。`index.ts` には載せない（メインバレルの公開面を変えないため）。
 * - 横断 API は experimental としてこのサブパスに限って公開する。
 * - `internal` から直接 re-export する（既存 sub-barrel の `errors.ts` と同じ実体を指す）。
 */

export type {
  NonceContext,
  NonceStore,
  NonceStoreAdapter,
  SeenNonceEntry,
} from '../internal/auth/index.js';
export { createNonceStore } from '../internal/auth/index.js';
export type { WellKnownJsonFailure } from '../internal/auth/well-known-json/index.js';
export { fetchWellKnownJson } from '../internal/auth/well-known-json/index.js';
export { parseIsoDateTimeMs } from '../internal/cache/iso-datetime.js';
export type { ErrorCode, VericertsErrorOptions } from '../internal/errors.js';
export { ErrorCodes, VericertsError } from '../internal/errors.js';
export type { FetchLike } from '../internal/fetch-di.js';
export type { BodyLimitOptions } from '../internal/http/body-limit.js';
export {
  declaresOversizedBody,
  MAX_DOCUMENT_BYTES,
  readBodyWithinLimit,
} from '../internal/http/body-limit.js';
export { isPublicHttpsUrl, isRedirectResponse } from '../internal/http/public-https-url.js';
export {
  fetchFollowingPublicRedirects,
  PublicRedirectRejection,
} from '../internal/http/public-redirect-fetch.js';
export { isHttpsUrl } from '../internal/https-url.js';
export type {
  CorrelationContext,
  CreateCorrelationContextInput,
} from '../internal/observability/correlation.js';
export {
  correlationHeaders,
  createCorrelationContext,
} from '../internal/observability/correlation.js';
export { isValidPinFormat, MIN_PIN_LENGTH } from '../internal/pin-policy.js';
export { isNonEmptyString } from '../internal/prototype-safety/non-empty-string.js';
export { parseJsonWithoutPrototype } from '../internal/prototype-safety/parse-json.js';
