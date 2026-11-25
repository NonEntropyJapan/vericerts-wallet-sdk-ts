/**
 * Wallet-to-Wallet（W2W）Migration モジュールの型定義・定数。
 *
 * 実装は backup（エクスポート・インポート）/ migration（デバイス移行プロトコル）/
 * lend（一時共有）に分割し、本ファイルへ型と定数を集約する。
 *
 * セキュリティ上の注意:
 * - 秘密（パスフレーズ / 平文 VC / 秘密鍵）は型のフィールドにも例外メッセージにも含めない。
 *   暗号文（`ciphertext`）と公開鍵座標（JWK）のみを保持する。
 */

import { ErrorCodes } from '../errors.js';

/** バックアップコンテナのバージョン。`WalletBackup.version`。 */
export const WALLET_BACKUP_VERSION = '1.0' as const;

/** バックアップ完全性証明（`IntegrityProof.alg`）の署名アルゴリズムは ES256 固定。 */
export const BACKUP_SIGNATURE_ALG = 'ES256' as const;

/** バックアップ本文の対称暗号アルゴリズム（`EncryptionHeader.alg`）は A256GCM 固定。 */
export const BACKUP_CONTENT_ALG = 'A256GCM' as const;

/** バックアップ用パスフレーズの最小文字数。 */
export const MIN_PASSPHRASE_LENGTH = 10;

/** Lend 期限監視のデフォルトポーリング間隔（ミリ秒）。 */
export const DEFAULT_LEND_EXPIRY_CHECK_INTERVAL_MS = 60_000;

/**
 * W2W の署名者公開鍵 JWK を非圧縮公開鍵へ変換する際の検証オプション。
 *
 * `backup.ts`（完全性証明）と `lend.ts`（lender_signature）が同一条件で
 * `jwkToUncompressedPublicKey` を呼ぶため共有する。JWK 自体の形式不正は 2001 とする。
 */
export const W2W_SIGNER_JWK_OPTIONS = {
  expectedCrv: 'P-256',
  errorCode: ErrorCodes.INVALID_DID,
} as const;

/**
 * 転送モード（`transfer_mode`）。
 * - `full`: 旧端末は転送後に VC を削除（移管）
 * - `selective`: 旧端末は維持
 * - `clone`: 緊急バックアップ（同時有効。監査で明示）
 */
export type TransferMode = 'full' | 'selective' | 'clone';

/** JSON Web Key（EC 公開鍵。`recipientKey` などで使用）。 */
export interface JWK {
  readonly kty: string;
  readonly crv?: string;
  readonly x?: string;
  readonly y?: string;
  readonly kid?: string;
  readonly [key: string]: unknown;
}

/** KDF パラメータ（`EncryptionHeader.kdfParams`）。`salt` は base64url。 */
export interface BackupKdfParams {
  readonly iterations?: number;
  readonly salt: string;
  /** `kdf: 'HKDF-SHA-256'` 専用の ECDH-ES エフェメラル公開鍵。不正は 4033（`backup-container-key.ts`）。 */
  readonly epk?: JWK;
}

/** 暗号ヘッダ（`EncryptionHeader`）。 */
export interface EncryptionHeader {
  readonly alg: typeof BACKUP_CONTENT_ALG;
  readonly kdf: 'HKDF-SHA-256' | 'PBKDF2-SHA-256';
  readonly kdfParams: BackupKdfParams;
  /** W2W-Transfer（受信者 1 名向け）の受信鍵。Wallet Swap（パスフレーズ）では省略。 */
  readonly recipientKey?: JWK;
  /** パスフレーズ保護か否か（`kdf: 'HKDF-SHA-256'` では `false`）。 */
  readonly passphraseProtected?: boolean;
}

/**
 * 暗号化された 1 エントリ（VC / Persona / DID / Settings 共通の単一型。`EncryptedEntry`）。
 *
 * `ciphertext` は base64url(暗号文 || GCM タグ)、`iv` は base64url(12 バイト IV)。`tag` は
 * Web Crypto が暗号文末尾に付す GCM タグ長（バイト）で、`ciphertext` からタグ部分を切り出す際の
 * 検証用メタ（実タグは `ciphertext` 末尾に含まれる）。
 */
export interface EncryptedEntry {
  /** 暗号化前エントリの識別子（VC は vcId、Persona は persona id 等）。 */
  readonly id: string;
  /** エントリ種別（`credential` / `persona` / `did` / `settings`）。 */
  readonly kind: 'credential' | 'persona' | 'did' | 'settings';
  /** VC の場合のフォーマット（例: `dc+sd-jwt`（新識別子）/ `vc+sd-jwt`（移行期間の旧識別子））。VC 以外は省略。 */
  readonly format?: string;
  /** base64url(暗号文 || 16 バイト GCM タグ)。 */
  readonly ciphertext: string;
  /** base64url(12 バイト IV)。 */
  readonly iv: string;
  /** GCM 認証タグ長（バイト）。`EncryptedEntry.tag`。 */
  readonly tag: number;
}

/** 完全性証明（`IntegrityProof`）。detached JWS（ES256）。 */
export interface IntegrityProof {
  readonly alg: typeof BACKUP_SIGNATURE_ALG;
  /** base64url の raw 署名（P1363 64 バイト）。 */
  readonly signature: string;
  /** 署名鍵の識別子（署名者の did:key など）。 */
  readonly signerKeyId: string;
}

/**
 * バックアップコンテナ（`WalletBackup`）。
 *
 * `credentials` / `personas` / `dids` は種別ごとの暗号化エントリ配列、`settings` は単一の
 * 暗号化エントリ。`integrity` は上記全体（`integrity` を除く）に対する ES256 detached 署名。
 */
export interface WalletBackup {
  readonly version: typeof WALLET_BACKUP_VERSION;
  /** 生成時刻（ISO 8601）。 */
  readonly createdAt: string;
  /** 元 Wallet の UUID。 */
  readonly walletId: string;
  /** 任意: 移行元 Provider。 */
  readonly walletProvider?: string;
  readonly encryption: EncryptionHeader;
  readonly credentials: readonly EncryptedEntry[];
  readonly personas: readonly EncryptedEntry[];
  readonly dids: readonly EncryptedEntry[];
  readonly settings: EncryptedEntry;
  readonly integrity: IntegrityProof;
}

/** エクスポート対象の平文アイテム（呼び出し側が Wallet 状態から組み立てて渡す）。 */
export interface BackupSourceItem {
  /** エントリ識別子。 */
  readonly id: string;
  /** VC の場合のフォーマット（例: `dc+sd-jwt`（新識別子）/ `vc+sd-jwt`（移行期間の旧識別子））。 */
  readonly format?: string;
  /** 平文の直列化済みデータ（VC 本文 / Persona メタ等の JSON 文字列やコンパクト表現）。 */
  readonly data: string;
}

/** エクスポート対象の Wallet 状態（平文）。`exportBackup` の入力。 */
export interface BackupSource {
  /** 元 Wallet の UUID。 */
  readonly walletId: string;
  /** 任意: 移行元 Provider。 */
  readonly walletProvider?: string;
  /** VC 群。 */
  readonly credentials: readonly BackupSourceItem[];
  /** Persona 群。 */
  readonly personas: readonly BackupSourceItem[];
  /** DID 群。 */
  readonly dids: readonly BackupSourceItem[];
  /** 設定（単一 JSON 文字列）。省略時は空オブジェクト相当。 */
  readonly settings?: string;
}

/**
 * `exportBackup` のオプション（`ExportOptions`）。
 *
 * `passphrase` は 10 文字以上、かつ zxcvbn スコア 3 以上を要求する。`signer` は
 * バックアップ全体に ES256 detached 署名を付す署名者。
 */
export interface ExportOptions {
  readonly passphrase: string;
  readonly includePersonas?: boolean;
  readonly includeVCs?: boolean;
  /** 除外する VC フォーマット（例: `ephemeral-demo-vc`）。 */
  readonly excludeFormats?: readonly string[];
  /** W2W-Transfer 用の受信者鍵。指定すると本文鍵は ECDH-ES + HKDF-SHA-256 で導出される。 */
  readonly recipientKey?: JWK;
  /** KDF 反復回数（PBKDF2）。省略時は既定値。`recipientKey` 指定時は無視される。 */
  readonly iterations?: number;
}

/** バックアップに ES256 署名を付す署名者。private key はクロージャに閉じ込め露出しない。 */
export interface BackupSigner {
  /** 署名鍵の識別子（`IntegrityProof.signerKeyId`）。 */
  readonly keyId: string;
  /** 署名者の EC 公開鍵 JWK（`crv: 'P-256'`）。検証に使う。 */
  readonly publicKeyJwk: JWK;
  /**
   * digest（署名対象の SHA-256）に ES256 署名し 64 バイト raw 署名を返す。
   * @param digest 署名対象のダイジェスト（32 バイト）。
   */
  sign(digest: Uint8Array): Uint8Array;
}

/** インポート結果（`ImportResult`）。 */
export interface ImportResult {
  /** 復元されたエントリの要約。 */
  readonly summary: {
    readonly vcCount: number;
    readonly personaCount: number;
    readonly didCount: number;
  };
  /** 復元された VC 群（復号済み平文）。 */
  readonly credentials: readonly BackupSourceItem[];
  /** 復元された Persona 群（復号済み平文）。 */
  readonly personas: readonly BackupSourceItem[];
  /** 復元された DID 群（復号済み平文）。 */
  readonly dids: readonly BackupSourceItem[];
  /** 復元された設定（復号済み平文。存在しなければ undefined）。 */
  readonly settings?: string;
  /** 競合した ID（既存と重複した VC など。呼び出し側が解決）。 */
  readonly conflicts: readonly string[];
  /** スキップしたエントリの理由（クレーム値を含まない）。SDK 自身のバックアップのインポートでは空。 */
  readonly warnings: readonly string[];
}

/** OOB Invitation（QR で表示。did:peer + nonce）。`startDeviceMigration` の戻り値。 */
export interface OOBInvitation {
  /** 招待の一意 ID。 */
  readonly id: string;
  /** 招待者（旧端末）の did:peer。 */
  readonly from: string;
  /** リプレイ防止 nonce（base64url）。 */
  readonly nonce: string;
  /** 招待の有効期限（エポック秒）。 */
  readonly expiresTime: number;
  /** QR / ディープリンク用の Invitation URI。 */
  readonly invitationUri: string;
}

/** 移行セッション（`MigrationSession`）。 */
export interface MigrationSession {
  readonly session_id: string;
  /** 相手（受信側 or 送信側）の DID。 */
  readonly theirDID: string;
  /** セッション状態。 */
  state: 'invited' | 'connected' | 'transferring' | 'completed' | 'aborted';
  /** 転送予定の VC 件数。 */
  credentialCount: number;
  /** リプレイ防止 nonce（招待由来）。 */
  readonly nonce: string;
}

/** 移行結果（`MigrationResult`）。 */
export interface MigrationResult {
  /** 転送成功件数。 */
  readonly transferred: number;
  /** 転送失敗した VC ID。 */
  readonly failed: readonly string[];
  /** cnf 再バインドが必要な VC ID。 */
  readonly rebindingRequired: readonly string[];
}

/** W2W DIDComm メッセージタイプ URI。 */
export const W2W_MESSAGE_TYPES = {
  TRANSFER_OFFER: 'https://vericerts.io/w2w/1.0/transfer-offer',
  TRANSFER_ACCEPT: 'https://vericerts.io/w2w/1.0/transfer-accept',
  TRANSFER_CREDENTIAL: 'https://vericerts.io/w2w/1.0/transfer-credential',
  TRANSFER_COMPLETE: 'https://vericerts.io/w2w/1.0/transfer-complete',
  TRANSFER_ABORT: 'https://vericerts.io/w2w/1.0/transfer-abort',
  LEND_REQUEST: 'https://vericerts.io/w2w/1.0/lend-request',
} as const;

/** Transfer-Offer メッセージ。 */
export interface TransferOfferMessage {
  readonly id: string;
  readonly type: typeof W2W_MESSAGE_TYPES.TRANSFER_OFFER;
  readonly from: string;
  readonly to: readonly string[];
  readonly created_time: number;
  readonly expires_time: number;
  readonly body: {
    readonly credential_count: number;
    readonly formats: readonly string[];
    readonly total_size_bytes: number;
    readonly require_passphrase: boolean;
    readonly transfer_mode: TransferMode;
  };
}

/** Lend トークン（lend-request の body を SDK 表現にしたもの）。 */
export interface LendToken {
  /** トークンの一意 ID（`revokeLend` で指定）。 */
  readonly id: string;
  /** 貸し出す VC の ID 群。 */
  readonly vc_ids: readonly string[];
  /** 有効期限（ISO 8601）。到達時に自動失効。 */
  readonly valid_until: string;
  /** 提示を許可する VC タイプ（例: `AgeOver18`）。省略時は制限なし。 */
  readonly allow_presentation_types?: readonly string[];
  /** 貸主（Lender）の DID。提示時に委任チェーン検証に使う。 */
  readonly lender_did: string;
  /** 受信者（借主）の DID。 */
  readonly recipient_did: string;
  /** 貸主の署名（detached JWS、base64url raw 署名）。 */
  readonly lender_signature: string;
}

/** Lend トークン作成の依存注入。 */
export interface CreateLendDependencies {
  /** トークン ID 生成（テスト注入用）。省略時は `crypto.randomUUID()`。 */
  readonly generateId?: () => string;
  /** 現在時刻（エポックミリ秒。テスト注入用）。省略時は `Date.now()`。 */
  readonly now?: () => number;
}
