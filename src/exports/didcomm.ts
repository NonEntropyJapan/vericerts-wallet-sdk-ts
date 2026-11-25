/**
 * DIDComm v2 メッセージの暗号化・送信、受信・復号、Out-of-Band Invitation の生成と処理、
 * issue-credential と present-proof のメッセージ組み立てに使う API。
 * 接続とメッセージの保存形式は、それぞれ `DIDCommConnection` と `DIDCommMessageRecord` が定義する。
 */

export type {
  IssueCredentialIssueOptions,
  IssueCredentialOfferOptions,
  IssueCredentialRequestOptions,
} from '../internal/didcomm/issue-credential.js';
export {
  buildIssueCredentialIssueMessage,
  buildIssueCredentialOfferMessage,
  buildIssueCredentialRequestMessage,
  extractIssuedCredentialJwt,
  ISSUE_CREDENTIAL_ISSUE_TYPE,
  ISSUE_CREDENTIAL_OFFER_TYPE,
  ISSUE_CREDENTIAL_REQUEST_TYPE,
} from '../internal/didcomm/issue-credential.js';
export type { DidCommJweDecryptResult, DidCommJweEncryptParams } from '../internal/didcomm/jwe.js';
export type {
  CreateOutOfBandInvitationOptions,
  ProcessedOutOfBandInvitation,
  ProcessOutOfBandInvitationOptions,
} from '../internal/didcomm/oob.js';
export {
  createOutOfBandInvitation,
  decodeOutOfBandInvitationUrl,
  encodeOutOfBandInvitationUrl,
  OUT_OF_BAND_INVITATION_TYPE,
  processOutOfBandInvitation,
} from '../internal/didcomm/oob.js';
export type { PackMessageOptions, UnpackedMessage } from '../internal/didcomm/pack.js';
export { packMessage, unpackMessage } from '../internal/didcomm/pack.js';
export type {
  BuildPresentationOptions,
  BuildPresentationRequestOptions,
} from '../internal/didcomm/present-proof.js';
export {
  buildPresentationMessage,
  buildPresentationRequestMessage,
  extractPresentationJwt,
  PRESENT_PROOF_PRESENTATION_TYPE,
  PRESENT_PROOF_REQUEST_TYPE,
} from '../internal/didcomm/present-proof.js';
export type { ReceiveDidCommMessageOptions } from '../internal/didcomm/receive.js';
export { receiveDIDCommMessage } from '../internal/didcomm/receive.js';
export type { ResolvedKeyAgreement } from '../internal/didcomm/resolve.js';
export { resolveKeyAgreement, resolveServiceEndpoint } from '../internal/didcomm/resolve.js';
export type { SendDidCommMessageOptions } from '../internal/didcomm/send.js';
export { sendDIDCommMessage } from '../internal/didcomm/send.js';
export type {
  DIDCommAttachment,
  DIDCommConnection,
  DIDCommConnectionState,
  DIDCommEncryptionMode,
  DIDCommKeyAgreementKeyPair,
  DIDCommMessageDirection,
  DIDCommMessageRecord,
  DIDCommPlaintextMessage,
  DIDCommResolver,
} from '../internal/didcomm/types.js';
