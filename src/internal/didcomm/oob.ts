/**
 * DIDComm v2 Out-of-Band Invitation の生成・処理。
 *
 * 1. `https://didcomm.org/out-of-band/2.0/invitation` メッセージを生成する。
 * 2. base64url エンコードし、`_oob` クエリパラメータとして URL へ埋め込む
 *    （QR コードはこの URL 文字列を入力にすればよく、画像生成自体は SDK のスコープ外）。
 * 3. 受信した Invitation URL をデコード・検証し、`DIDCommConnection`（`invited` 状態）へ反映する。
 *
 * セキュリティ上の注意:
 * - 例外メッセージ・`context` に DID 文字列・Invitation 本文を含めない。
 */

import { base64urlnopad } from '@scure/base';
import { ErrorCodes, VericertsError } from '../errors.js';
import { ownProperty } from '../prototype-safety/own-property.js';
import type { DIDCommConnection, DIDCommPlaintextMessage } from './types.js';

/** OOB Invitation メッセージの `type`（DIDComm Messaging v2.1 `out-of-band/2.0/invitation`）。 */
export const OUT_OF_BAND_INVITATION_TYPE = 'https://didcomm.org/out-of-band/2.0/invitation';

/** `_oob` クエリパラメータ名（DIDComm OOB Invitation の慣例）。 */
const OOB_QUERY_PARAM = '_oob';

/** `createOutOfBandInvitation` のオプション。 */
export interface CreateOutOfBandInvitationOptions {
  /** 招待者の DID（`from` に載る）。 */
  readonly inviterDid: string;
  /** 招待の目的コード（機械可読）。 */
  readonly goalCode?: string;
  /** 招待の目的（人間可読）。 */
  readonly goal?: string;
  /** 受理可能なメッセージフォーマット。 */
  readonly accept?: readonly string[];
  /** 招待に続くハンドシェイクプロトコル URI（例: DIDComm connect protocol）。 */
  readonly handshakeProtocols?: readonly string[];
}

/**
 * OOB Invitation メッセージ（DIDComm v2 平文メッセージ）を生成する。
 *
 * @param options 招待者 DID・目的・受理フォーマット等。
 * @returns `type: https://didcomm.org/out-of-band/2.0/invitation` の平文メッセージ。
 */
export function createOutOfBandInvitation(
  options: CreateOutOfBandInvitationOptions,
): DIDCommPlaintextMessage {
  // 任意フィールドは own 限定（汚染値が相手へ送る招待の body に混入しない）。
  const goalCode = ownProperty<string>(options, 'goalCode');
  const goal = ownProperty<string>(options, 'goal');
  const accept = ownProperty<readonly string[]>(options, 'accept');
  const handshakeProtocols = ownProperty<readonly string[]>(options, 'handshakeProtocols');
  return {
    id: crypto.randomUUID(),
    type: OUT_OF_BAND_INVITATION_TYPE,
    from: options.inviterDid,
    body: {
      ...(goalCode !== undefined ? { goal_code: goalCode } : {}),
      ...(goal !== undefined ? { goal } : {}),
      ...(accept !== undefined ? { accept } : {}),
      ...(handshakeProtocols !== undefined ? { handshake_protocols: handshakeProtocols } : {}),
    },
  };
}

/**
 * OOB Invitation を base64url エンコードし、`baseUrl` の `_oob` クエリパラメータへ埋め込んだ
 * URL 文字列を返す（QR コード・ディープリンク等への配布形式として使う）。
 *
 * @param invitation `createOutOfBandInvitation` が返した Invitation。
 * @param baseUrl 配布用ベース URL（招待者のランディングページ等）。
 * @returns `_oob` パラメータ付きの URL 文字列。
 * @throws `baseUrl` が不正な URI 形式の場合（`OOB_INVITATION_PARSE_FAILED`）。
 */
export function encodeOutOfBandInvitationUrl(
  invitation: DIDCommPlaintextMessage,
  baseUrl: string,
): string {
  let url: URL;
  try {
    url = new URL(baseUrl);
  } catch {
    throw new VericertsError(ErrorCodes.OOB_INVITATION_PARSE_FAILED);
  }
  url.searchParams.set(
    OOB_QUERY_PARAM,
    base64urlnopad.encode(new TextEncoder().encode(JSON.stringify(invitation))),
  );
  return url.toString();
}

function validateInvitation(value: unknown): DIDCommPlaintextMessage {
  if (typeof value !== 'object' || value === null) {
    throw new VericertsError(ErrorCodes.OOB_INVITATION_INVALID);
  }
  const id = ownProperty<unknown>(value, 'id');
  const type = ownProperty<unknown>(value, 'type');
  const from = ownProperty<unknown>(value, 'from');
  const body = ownProperty<unknown>(value, 'body');
  if (
    typeof id !== 'string' ||
    type !== OUT_OF_BAND_INVITATION_TYPE ||
    typeof from !== 'string' ||
    typeof body !== 'object' ||
    body === null
  ) {
    throw new VericertsError(ErrorCodes.OOB_INVITATION_INVALID);
  }
  return value as DIDCommPlaintextMessage;
}

/**
 * `encodeOutOfBandInvitationUrl` が返した URL をデコードし、構造を検証する。
 *
 * @param url `_oob` クエリパラメータ付きの Invitation URL。
 * @returns デコード・検証済みの Invitation（`DIDCommPlaintextMessage`）。
 * @throws URL / `_oob` パラメータ欠落 / base64url 形式不正の場合（`OOB_INVITATION_PARSE_FAILED`）、
 *         デコード後の JSON 構造が Invitation として不正な場合（`OOB_INVITATION_INVALID`）。
 */
export function decodeOutOfBandInvitationUrl(url: string): DIDCommPlaintextMessage {
  let encoded: string | null;
  try {
    encoded = new URL(url).searchParams.get(OOB_QUERY_PARAM);
  } catch {
    throw new VericertsError(ErrorCodes.OOB_INVITATION_PARSE_FAILED);
  }
  if (encoded === null) {
    throw new VericertsError(ErrorCodes.OOB_INVITATION_PARSE_FAILED);
  }
  let decoded: unknown;
  try {
    decoded = JSON.parse(new TextDecoder().decode(base64urlnopad.decode(encoded)));
  } catch {
    throw new VericertsError(ErrorCodes.OOB_INVITATION_PARSE_FAILED);
  }
  return validateInvitation(decoded);
}

/** `processOutOfBandInvitation` の結果。 */
export interface ProcessedOutOfBandInvitation {
  /** `invited` 状態で構築された接続レコード（永続化は呼び出し側の責務）。 */
  readonly connection: DIDCommConnection;
  /** デコード・検証済みの Invitation 本体。 */
  readonly invitation: DIDCommPlaintextMessage;
}

/** `processOutOfBandInvitation` のオプション。 */
export interface ProcessOutOfBandInvitationOptions {
  /** 接続 ID。省略時は `crypto.randomUUID()`。 */
  readonly connectionId?: string;
}

/**
 * 受信した Invitation URL をデコード・検証し、`invited` 状態の `DIDCommConnection` を構築する。
 *
 * @param url `_oob` クエリパラメータ付きの Invitation URL。
 * @param myDid 自分の DID（`DIDCommConnection.myDID`）。
 * @param options 接続 ID の上書き（省略可）。
 * @returns 構築された接続レコードとデコード済み Invitation。
 * @throws `decodeOutOfBandInvitationUrl` と同じ（`OOB_INVITATION_PARSE_FAILED` /
 *         `OOB_INVITATION_INVALID`）。
 */
export function processOutOfBandInvitation(
  url: string,
  myDid: string,
  options?: ProcessOutOfBandInvitationOptions,
): ProcessedOutOfBandInvitation {
  const invitation = decodeOutOfBandInvitationUrl(url);
  // `validateInvitation` が `from` を string に絞り込み済み（デコード経路のみ検証を通る）。
  const theirDID = ownProperty<string>(invitation, 'from') as string;
  const connection: DIDCommConnection = {
    id:
      (options === undefined ? undefined : ownProperty<string>(options, 'connectionId')) ??
      crypto.randomUUID(),
    myDID: myDid,
    theirDID,
    state: 'invited',
    createdAt: new Date().toISOString(),
  };
  return { connection, invitation };
}
