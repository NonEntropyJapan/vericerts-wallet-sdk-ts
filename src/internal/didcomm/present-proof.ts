/**
 * DIDComm v2 の present-proof/3.0 メッセージの構築・抽出。
 *
 * VP の署名自体は `credential/presentation/issue.ts` の
 * `issuePresentation` / `issuePresentationAsync` が担う（本モジュールはそれをスコープ外にせず、
 * 署名済み JWT-VP を DIDComm メッセージの添付ファイルとして運ぶ transport 層のみを提供する）。
 *
 * プロトコルフロー（DIF DIDComm Present Proof Protocol 3.0 準拠）:
 * 1. Verifier → Holder: `request-presentation`（`presentationDefinition` で要求内容を提示）
 * 2. Holder → Verifier: `presentation`（署名済み JWT-VP を添付。request の `thid` を引き継ぐ）
 *
 * `issue-credential.ts` と同じスレッド機構（`thid` = 起点メッセージの `id`）を使う。
 */

import { base64 } from '@scure/base';
import { ErrorCodes, VericertsError } from '../errors.js';
import { ownProperty } from '../prototype-safety/own-property.js';
import { firstBase64Attachment } from './attachment.js';
import { commentBody } from './comment-body.js';
import type { DIDCommAttachment, DIDCommPlaintextMessage } from './types.js';

/** present-proof プロトコルのメッセージタイプ URI。 */
export const PRESENT_PROOF_REQUEST_TYPE =
  'https://didcomm.org/present-proof/3.0/request-presentation';
export const PRESENT_PROOF_PRESENTATION_TYPE = 'https://didcomm.org/present-proof/3.0/presentation';

/** JWT-VP 添付の media type（present-proof attachment format）。 */
const PRESENTATION_ATTACHMENT_MEDIA_TYPE = 'application/vp+jwt';
/** JWT-VP 添付の固定 `attach_id`（1 メッセージにつき VP 1 件のため固定値で足りる）。 */
const PRESENTATION_ATTACHMENT_ID = 'presentation-jwt';

/** `buildPresentationRequestMessage` のオプション。 */
export interface BuildPresentationRequestOptions {
  /** Verifier の DID（`from`）。 */
  readonly fromDid: string;
  /** Holder の DID（`to`）。 */
  readonly toDid: string;
  /** 提示要求の内容（OID4VP `presentation_definition` 相当。形式は呼び出し側の合意に委ねる）。 */
  readonly presentationDefinition: Readonly<Record<string, unknown>>;
  /** 人間可読なコメント。 */
  readonly comment?: string;
}

/**
 * `request-presentation` メッセージ（提示要求）を構築する。
 *
 * @param options Verifier/Holder DID と提示要求内容。
 * @returns スレッドの起点となる `request-presentation` メッセージ（`id` が以降の `thid` になる）。
 */
export function buildPresentationRequestMessage(
  options: BuildPresentationRequestOptions,
): DIDCommPlaintextMessage {
  return {
    id: crypto.randomUUID(),
    type: PRESENT_PROOF_REQUEST_TYPE,
    from: options.fromDid,
    to: [options.toDid],
    body: {
      presentation_definition: options.presentationDefinition,
      ...commentBody(options),
    },
  };
}

/** `buildPresentationMessage` のオプション。 */
export interface BuildPresentationOptions {
  /** Holder の DID（`from`）。 */
  readonly fromDid: string;
  /** Verifier の DID（`to`）。 */
  readonly toDid: string;
  /** 応答対象の `request-presentation` メッセージの `id`（スレッドを継続する）。 */
  readonly requestId: string;
  /** 署名済み JWT-VP（`issuePresentation` / `issuePresentationAsync` の戻り値）。 */
  readonly presentationJwt: string;
  /** 人間可読なコメント。 */
  readonly comment?: string;
}

/**
 * `presentation` メッセージ（署名済み JWT-VP を添付して送付）を構築する。
 *
 * @param options Holder/Verifier DID・応答対象の request メッセージ id・署名済み JWT-VP。
 * @returns `thid: options.requestId` を引き継ぎ、`presentationJwt` を base64 添付した
 *          `presentation` メッセージ。
 */
export function buildPresentationMessage(
  options: BuildPresentationOptions,
): DIDCommPlaintextMessage {
  const attachment: DIDCommAttachment = {
    id: PRESENTATION_ATTACHMENT_ID,
    media_type: PRESENTATION_ATTACHMENT_MEDIA_TYPE,
    data: { base64: base64.encode(new TextEncoder().encode(options.presentationJwt)) },
  };
  return {
    id: crypto.randomUUID(),
    type: PRESENT_PROOF_PRESENTATION_TYPE,
    from: options.fromDid,
    to: [options.toDid],
    thid: options.requestId,
    body: commentBody(options),
    attachments: [attachment],
  };
}

/**
 * `presentation` メッセージから署名済み JWT-VP を取り出す。
 *
 * @param message 受信した `presentation` メッセージ。
 * @returns 添付から復元した JWT-VP 文字列。
 * @throws `type` が `presentation` でない、添付が無い、base64 デコードに失敗する場合
 *         （`DIDCOMM_UNPACKING_FAILED`。メッセージ構造不正のため既存コードを再利用する）。
 */
export function extractPresentationJwt(message: DIDCommPlaintextMessage): string {
  // `type` / 添付は受信メッセージの値なので own 限定で読む。
  if (ownProperty<unknown>(message, 'type') !== PRESENT_PROOF_PRESENTATION_TYPE) {
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
