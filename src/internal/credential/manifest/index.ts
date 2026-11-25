/**
 * DIF Credential Manifest モジュールの公開エントリ（Holder 側）。
 *
 * 型（`types.ts`）・取得/パース（`parse.ts`）・申請構築（`application-build.ts`）・
 * 提出/レスポンス処理（`application-response.ts`）を集約して再エクスポートする。credential
 * モジュールの `index.ts` からさらに再エクスポートされる。
 */

export { buildCredentialApplication } from './application-build.js';
export {
  processCredentialResponse,
  submitCredentialApplication,
} from './application-response.js';
export { fetchCredentialManifest, parseCredentialManifest } from './parse.js';
export type {
  ApplicationResult,
  BuildApplicationOptions,
  CredentialApplication,
  CredentialManifest,
  DisplayMapping,
  FormatRequirement,
  ManifestAnswers,
  ManifestDependencies,
  ManifestIssuer,
  ManifestStyle,
  OutputDescriptor,
  PresentationDefinition,
  PresentationSubmission,
  PresentationSubmissionDescriptor,
  SubmitApplicationDependencies,
} from './types.js';
