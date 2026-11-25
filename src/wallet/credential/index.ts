/**
 * wallet の credential サブモジュールの公開エントリ（sub-barrel）。
 *
 * VC / VP / SD-JWT に関するファサード API 型（`api.ts` / 検証 API は `verify-api.ts`）、`WalletImpl`
 * から委譲される発行・検証の実処理（`ops.ts`、高レベル Verifier API は `verify-result.ts`）、
 * OID4VCI 受領の実処理（`receive.ts`。300 行上限のため `ops.ts` から分離）を
 * 再エクスポートする。ファサード本体（`../wallet.ts`）は本バレル経由でのみ本サブモジュールを
 * 参照する。
 */

export type {
  PresentationApi,
  ReceiveCredentialOptions,
  ReceivedVerifiableCredential,
  VerifySdJwtFacadeOptions,
} from './api.js';
export { createPresentationWith } from './create-presentation.js';
export type { CreatedPresentation } from './create-presentation-api.js';
export { matchCredentialsWith } from './match.js';
export type { MatchCredentialsOptions } from './match-api.js';
export { matchCredentialsByPresentationDefinitionWith } from './match-by-presentation-definition.js';
export {
  issueCredentialWith,
  issuePresentationWith,
  issueSdJwtWith,
  verifyCredentialWith,
  verifySdJwtWith,
} from './ops.js';
export { receiveCredentialWith } from './receive.js';
export type {
  VerifyApi,
  VerifyCredentialFacadeOptions,
  VerifyPresentationFacadeOptions,
} from './verify-api.js';
export {
  verifyCredentialResultWith,
  verifyPresentationEnvelopeStrictWith,
  verifyPresentationResultWith,
} from './verify-result.js';
