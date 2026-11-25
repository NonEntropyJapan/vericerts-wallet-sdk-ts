/**
 * DIDComm 接続と、接続上で送受信したメッセージの記録。
 * と、DIDComm v2 暗号メッセージングが使う型定義。
 *
 * DIDComm v2 で確立された P2P 接続の永続化レコードの形状に加え、ワイヤー上でやり取りする
 * 平文メッセージ（`DIDCommPlaintextMessage`）・keyAgreement 鍵ペア・DID 解決 DI の契約を提供する。
 * `DIDCommMessageRecord.body` は永続化された平文 JSON（復号後・署名検証後）を表し、ワイヤー上の
 * JWE Compact Serialization そのものは `didcomm/jwe.ts` が文字列として扱う。
 */

import type { DIDDocument } from '../identity/did.js';

/** DIDComm v2 接続の状態。 */
export type DIDCommConnectionState = 'invited' | 'requested' | 'completed';

/** DIDComm v2 で確立された P2P 接続情報。`id` が storage 上の主キー。 */
export interface DIDCommConnection {
  /** 接続 ID（UUID）。 */
  readonly id: string;
  /** 自分の DID（通常 did:peer）。 */
  readonly myDID: string;
  /** 相手の DID。 */
  readonly theirDID: string;
  /** 接続状態。 */
  readonly state: DIDCommConnectionState;
  /** Mediator DID（経由時のみ）。 */
  readonly mediatorDID?: string;
  /** 接続確立日時（ISO 8601）。 */
  readonly createdAt: string;
  /** 最終メッセージ日時（ISO 8601）。 */
  readonly lastMessageAt?: string;
}

/** メッセージの送受信方向。 */
export type DIDCommMessageDirection = 'sent' | 'received';

/**
 * DIDCommConnection 上で送受信されたメッセージの永続化レコード。
 *
 * `body` は平文 JSON として保持する型定義であり、DIDComm v2 の JWE/JWS 封筒化・復号・署名検証は
 * 行わない（上記スコープ注記を参照）。
 */
export interface DIDCommMessageRecord {
  /** メッセージ ID（UUID）。 */
  readonly id: string;
  /** 接続 ID（`DIDCommConnection.id` への外部キー）。 */
  readonly connectionId: string;
  /** メッセージタイプ URI。 */
  readonly type: string;
  /** 送受信方向。 */
  readonly direction: DIDCommMessageDirection;
  /** メッセージ本体（JSON）。 */
  readonly body: Record<string, unknown>;
  /** 送受信日時（ISO 8601）。 */
  readonly createdAt: string;
}

/** メッセージ添付ファイル（DIDComm v2 `attachments`。base64 / json / links のいずれか 1 つを持つ）。 */
export interface DIDCommAttachment {
  /** 添付 ID（省略可）。 */
  readonly id?: string;
  /** MIME メディアタイプ（省略可）。 */
  readonly media_type?: string;
  /** 添付データ本体。 */
  readonly data: {
    readonly base64?: string;
    readonly json?: unknown;
    readonly links?: readonly string[];
  };
}

/**
 * DIDComm v2 平文メッセージ（ワイヤー上の envelope。DIDComm Messaging spec v2.1 の
 * plaintext message structure に対応）。JWE で暗号化される前 / 復号された後の形。
 */
export interface DIDCommPlaintextMessage {
  /** メッセージ ID（UUID）。送受信双方で同一メッセージを指すのに使う。 */
  readonly id: string;
  /** メッセージタイプ URI（例: `https://didcomm.org/out-of-band/2.0/invitation`）。 */
  readonly type: string;
  /** 送信者 DID。Anoncrypt では省略され得る。 */
  readonly from?: string;
  /** 宛先 DID の一覧。 */
  readonly to?: readonly string[];
  /** 作成日時（UNIX epoch 秒）。 */
  readonly created_time?: number;
  /** 有効期限（UNIX epoch 秒）。 */
  readonly expires_time?: number;
  /** スレッド ID（返信の紐付け）。省略時は `id` がスレッド ID を兼ねる。 */
  readonly thid?: string;
  /** 親スレッド ID（Invitation 起点のスレッド等）。 */
  readonly pthid?: string;
  /** メッセージ本体（type ごとのペイロード）。 */
  readonly body: Record<string, unknown>;
  /** 添付ファイル。 */
  readonly attachments?: readonly DIDCommAttachment[];
}

/** DIDComm v2 keyAgreement 鍵ペア（P-256。JWE の ECDH-ES 鍵合意に使う）。 */
export interface DIDCommKeyAgreementKeyPair {
  /** 公開鍵 JWK（`crv: P-256`）。 */
  readonly publicKeyJwk: Readonly<Record<string, unknown>>;
  /** 秘密鍵（raw scalar、32 バイト）。 */
  readonly privateKey: Uint8Array;
  /** DID Document 上の keyAgreement VerificationMethod id（`kid` として JWE header に載せる）。 */
  readonly id?: string;
}

/**
 * DID 解決 DI の最小契約。`identity/resolver.ts` の `Resolver` はこの形を満たすため、
 * 呼び出し側は `Resolver` インスタンスをそのまま渡せる。
 */
export interface DIDCommResolver {
  resolve(did: string): Promise<DIDDocument>;
}

/** Authcrypt（送信者署名あり）/ Anoncrypt（署名なし）の選択。省略時は `'anoncrypt'`。 */
export type DIDCommEncryptionMode = 'authcrypt' | 'anoncrypt';
