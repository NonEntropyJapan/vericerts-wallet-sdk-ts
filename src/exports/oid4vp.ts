/**
 * 用途別 entry `vericerts-wallet-sdk/oid4vp`。
 *
 * サブパス専用バレル。利用契約レジストリでこの entry に割り当てられた定義だけを公開する。
 * `createPresentation` は解析済み要求を受け取る関数で、root の `Wallet.createPresentation`
 * （要求 URI と VC ID を受け取るメソッド）とは異なる。`index.ts` には本バレルを載せない。
 */

export {
  type CreatedPresentation,
  type CreatePresentationOptions,
  createPresentation,
  type LoaCheck,
  type PresentationMetadata,
} from '../internal/auth/create-presentation/index.js';
export { createDcqlWorkBudget } from '../internal/auth/dcql/budget.js';
export {
  type CredentialMatch,
  type DcqlClaim,
  type DcqlMeta,
  findMatchingCredentialIndexes,
} from '../internal/auth/dcql/dcql.js';
export type {
  DcqlCredential,
  DcqlQuery,
  QueryableCredential,
} from '../internal/auth/index.js';
export {
  evaluateDcql,
  FORMAT_SD_JWT_VC,
  FORMAT_SD_JWT_VC_DC,
  generateIDToken,
  parsePresentationRequest,
  parseSIOPv2Request,
  processSIOPv2Request,
  toQueryableFromVc,
  verifyIDToken,
} from '../internal/auth/index.js';
export type { PresentationRequest } from '../internal/auth/request.js';

import type { WorkBudget } from '../internal/primitives/work-budget.js';

/** DCQL の複数回評価で共有する変更可能な仕事量予算。 */
export type DcqlWorkBudget = WorkBudget;
