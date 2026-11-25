/**
 * DIDComm v2 の issue-credential/3.0 メッセージの構築・抽出。
 *
 * VC の署名自体は `credential/vc/issue.ts` の `issueCredential` /
 * `issueCredentialAsync` が担う（本モジュールはそれをスコープ外にせず、発行済み JWT-VC を
 * DIDComm メッセージの添付ファイルとして運ぶ transport 層のみを提供する）。
 *
 * プロトコルフロー（DIF DIDComm Issue Credential Protocol 3.0 準拠）:
 * 1. Issuer → Holder: `offer-credential`（`credentialPreview` で発行内容を提示）
 * 2. Holder → Issuer: `request-credential`（offer の `thid` を引き継いで発行を要求）
 * 3. Issuer → Holder: `issue-credential`（発行済み JWT-VC を添付。request の `thid` を引き継ぐ）
 *
 * `id` はメッセージ単体の識別子、`thid`（thread id）は 3 メッセージを 1 つのやり取りとして
 * 束ねる識別子（DIDComm Messaging spec v2.1 のスレッド機構）。`offer-credential` には `thid` を
 * 付けず自身の `id` がスレッドの起点になる。以降のメッセージは offer の `id` を `thid` として運ぶ。
 */

import { base64 } from '@scure/base';
import { ErrorCodes, VericertsError } from '../errors.js';
import { ownProperty } from '../prototype-safety/own-property.js';
import { firstBase64Attachment } from './attachment.js';
import { commentBody } from './comment-body.js';
import type { DIDCommAttachment, DIDCommPlaintextMessage } from './types.js';

/** issue-credential プロトコルのメッセージタイプ URI。 */
export const ISSUE_CREDENTIAL_OFFER_TYPE =
  'https://didcomm.org/issue-credential/3.0/offer-credential';
export const ISSUE_CREDENTIAL_REQUEST_TYPE =
  'https://didcomm.org/issue-credential/3.0/request-credential';
export const ISSUE_CREDENTIAL_ISSUE_TYPE =
  'https://didcomm.org/issue-credential/3.0/issue-credential';

/** JWT-VC 添付の media type（issue-credential attachment format）。 */
const CREDENTIAL_ATTACHMENT_MEDIA_TYPE = 'application/vc+jwt';
/** JWT-VC 添付の固定 `attach_id`（1 メッセージにつき VC 1 件のため固定値で足りる）。 */
const CREDENTIAL_ATTACHMENT_ID = 'credential-jwt';

/** `buildIssueCredentialOfferMessage` のオプション。 */
export interface IssueCredentialOfferOptions {
  /** Issuer の DID（`from`）。 */
  readonly fromDid: string;
  /** Holder の DID（`to`）。 */
  readonly toDid: string;
  /** 発行予定の VC クレームプレビュー（`credential_preview`。人間可読な提示内容）。 */
  readonly credentialPreview: Readonly<Record<string, unknown>>;
  /** 人間可読なコメント。 */
  readonly comment?: string;
}

/**
 * `offer-credential` メッセージ（発行内容のプレビューを提示）を構築する。
 *
 * @param options Issuer/Holder DID とプレビュー内容。
 * @returns スレッドの起点となる `offer-credential` メッセージ（`id` が以降の `thid` になる）。
 */
export function buildIssueCredentialOfferMessage(
  options: IssueCredentialOfferOptions,
): DIDCommPlaintextMessage {
  return {
    id: crypto.randomUUID(),
    type: ISSUE_CREDENTIAL_OFFER_TYPE,
    from: options.fromDid,
    to: [options.toDid],
    body: {
      credential_preview: options.credentialPreview,
      ...commentBody(options),
    },
  };
}

/** `buildIssueCredentialRequestMessage` のオプション。 */
export interface IssueCredentialRequestOptions {
  /** Holder の DID（`from`）。 */
  readonly fromDid: string;
  /** Issuer の DID（`to`）。 */
  readonly toDid: string;
  /** 応答対象の `offer-credential` メッセージの `id`（スレッドを継続する）。 */
  readonly offerId: string;
  /** 人間可読なコメント。 */
  readonly comment?: string;
}

/**
 * `request-credential` メッセージ（offer を受けて発行を要求）を構築する。
 *
 * @param options Holder/Issuer DID と応答対象の offer メッセージ id。
 * @returns `thid: options.offerId` を引き継いだ `request-credential` メッセージ。
 */
export function buildIssueCredentialRequestMessage(
  options: IssueCredentialRequestOptions,
): DIDCommPlaintextMessage {
  return {
    id: crypto.randomUUID(),
    type: ISSUE_CREDENTIAL_REQUEST_TYPE,
    from: options.fromDid,
    to: [options.toDid],
    thid: options.offerId,
    body: commentBody(options),
  };
}

/** `buildIssueCredentialIssueMessage` のオプション。 */
export interface IssueCredentialIssueOptions {
  /** Issuer の DID（`from`）。 */
  readonly fromDid: string;
  /** Holder の DID（`to`）。 */
  readonly toDid: string;
  /** 応答対象の `request-credential` メッセージの `id`（スレッドを継続する）。 */
  readonly requestId: string;
  /** 発行済み JWT-VC（`issueCredential` / `issueCredentialAsync` の戻り値）。 */
  readonly credentialJwt: string;
  /** 人間可読なコメント。 */
  readonly comment?: string;
}

/**
 * `issue-credential` メッセージ（発行済み JWT-VC を添付して送付）を構築する。
 *
 * @param options Issuer/Holder DID・応答対象の request メッセージ id・発行済み JWT-VC。
 * @returns `thid: options.requestId` を引き継ぎ、`credentialJwt` を base64 添付した
 *          `issue-credential` メッセージ。
 */
export function buildIssueCredentialIssueMessage(
  options: IssueCredentialIssueOptions,
): DIDCommPlaintextMessage {
  const attachment: DIDCommAttachment = {
    id: CREDENTIAL_ATTACHMENT_ID,
    media_type: CREDENTIAL_ATTACHMENT_MEDIA_TYPE,
    data: { base64: base64.encode(new TextEncoder().encode(options.credentialJwt)) },
  };
  return {
    id: crypto.randomUUID(),
    type: ISSUE_CREDENTIAL_ISSUE_TYPE,
    from: options.fromDid,
    to: [options.toDid],
    thid: options.requestId,
    body: commentBody(options),
    attachments: [attachment],
  };
}

/**
 * `issue-credential` メッセージから発行済み JWT-VC を取り出す。
 *
 * @param message 受信した `issue-credential` メッセージ。
 * @returns 添付から復元した JWT-VC 文字列。
 * @throws `type` が `issue-credential` でない、添付が無い、base64 デコードに失敗する場合
 *         （`DIDCOMM_UNPACKING_FAILED`。メッセージ構造不正のため既存コードを再利用する）。
 */
export function extractIssuedCredentialJwt(message: DIDCommPlaintextMessage): string {
  // `type` / 添付は受信メッセージの値なので own 限定で読む。
  if (ownProperty<unknown>(message, 'type') !== ISSUE_CREDENTIAL_ISSUE_TYPE) {
    throw new VericertsError(ErrorCodes.DIDCOMM_UNPACKING_FAILED);
  }
  const encoded = firstBase64Attachment(message);
  if (typeof encoded !== 'string') {
    throw new VericertsError(ErrorCodes.DIDCOMM_UNPACKING_FAILED);
  }
  try {
    return new TextDecoder().decode(base64.decode(encoded));
  } catch {
    throw new VericertsError(ErrorCodes.DIDCOMM_UNPACKING_FAILED);
  }
}
