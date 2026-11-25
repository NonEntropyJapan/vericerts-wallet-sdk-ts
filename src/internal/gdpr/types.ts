/**
 * GDPR Compliance API の内部型定義。
 *
 * `gdpr` モジュールが扱う 2 つの永続化対象を定義する:
 * - `CredentialRecord`: Wallet がローカル保持する VC 本体 + Wallet メタデータ（`disputed` 等）。
 *   VC 本体の署名には影響しない Wallet 側のフラグを付帯する。
 * - `DashboardLogEntry`: Dashboard ログの 1 エントリ。JWS 署名と Merkle chain の
 *   `prevHash` で改ざん検知可能にする。
 *
 * `LogEntryType` は全種別を型として定義するが、記録の実装は Phase ごとに追加してきた。
 * 実装済みの追記経路は `correctionRequest`/ `consentRevoked`/
 * `credentialDeleted`/ `transferWarning`/ `failOpenPolicy`/
 * `transactionDataConsent`（`recordTransactionDataConsent`）/ `presentation`
 * （`logPresentationEvent`）/ `unlock` / `authFailure`（extension 側のバッファ flush 経由）/
 * `logEntryDeleted`（個別 / フィルタ削除の構造的証跡）である。残りの種別は後続 Phase で追記する。
 */

import type { VerifiableCredential } from '../credential/index.js';

/**
 * Dashboard ログのエントリ種別（`LogEntryType`）。
 *
 * 全種別を型として定義するが、記録の実装は各 Phase で追加する。`correctionRequest`/
 * `consentRevoked`に加え、`credentialDeleted`（Art.17 削除の監査記録）・
 * `transferWarning`（EU 域外転送警告、`transfer_warning`）・`failOpenPolicy`
 * （Fail-open 判定の監査レコード）・`transactionDataConsent`
 * （`recordTransactionDataConsent`）・`presentation`（`logPresentationEvent`）・
 * `emergencyRevoked`（`emergencyRevokeValidator`）を扱う。
 */
export type LogEntryType =
  | 'unlock'
  | 'presentation'
  | 'credentialReceived'
  | 'pseudonymDerived'
  | 'transactionDataConsent'
  | 'correctionRequest'
  | 'consentGranted'
  | 'consentRevoked'
  | 'credentialDeleted'
  | 'transferWarning'
  | 'authFailure'
  | 'failOpenPolicy'
  | 'logEntryDeleted'
  | 'emergencyRevoked';

/**
 * VC の提示履歴 1 件（`recordPresentation` が追記）。
 *
 * `revokeConsent` の `rpIdentifier` / `purpose` スコープ解決に用いる最小限のフィールドのみを持つ
 * （提示先 RP・目的・日時のみ。開示したクレームの値やその他の提示メタデータは含めない）。
 */
export interface PresentedToEntry {
  /** 提示先 RP の識別子。 */
  readonly rpIdentifier: string;
  /** 提示の目的（RP が宣言した purpose。指定時のみ）。 */
  readonly purpose?: string;
  /** 提示日時（ISO 8601）。 */
  readonly presentedAt: string;
}

/**
 * Wallet がローカル保持する VC レコード。
 *
 * VC 本体（`credential`）に加え、Wallet 側で管理するメタデータを保持する。`disputed` は GDPR
 * Art.16 訂正権のフォールバックとして `markCredentialDisputed` が付与するフラグ、`processingRestricted`
 * は GDPR Art.18 処理制限権として `setCredentialProcessingRestriction` が付与するフラグ。いずれも
 * VC 本体の署名には影響しない。
 */
export interface CredentialRecord {
  /** VC の ID（storage キー・`markCredentialDisputed` の `vcId` に対応）。 */
  readonly id: string;
  /** 保持している VC 本体。 */
  readonly credential: VerifiableCredential;
  /** 受領日時（ISO 8601）。 */
  readonly receivedAt: string;
  /** 訂正要求中フラグ（Art.16 フォールバック）。既定は未設定（= false 相当）。 */
  readonly disputed?: boolean;
  /** 訂正要求の理由。`disputed` が true のときに設定する（Dashboard ログにも記録する）。 */
  readonly disputeReason?: string;
  /** 訂正要求を記録した日時（ISO 8601）。 */
  readonly disputedAt?: string;
  /**
   * 処理制限中フラグ（Art.18 処理制限権）。`true` の VC は `matchCredentials()` /
   * `matchCredentialsByPresentationDefinition()` の提示候補から除外される（VC 本体は削除しない）。
   * 既定は未設定（= false 相当）。
   */
  readonly processingRestricted?: boolean;
  /** 処理制限フラグを更新した日時（ISO 8601）。`setCredentialProcessingRestriction` 呼び出し時に設定する。 */
  readonly restrictionUpdatedAt?: string;
  /**
   * 法的保持（legal hold）フラグ（GDPR Art.17(3)(b) 該当）。`true` の VC は法的義務
   * により削除できず、`deleteCredential` が `GDPR_LEGAL_OBLIGATION`(10602) を送出する。Issuer サーバー運用
   * ログ等、Controller が法的義務で保持する VC を組込先が受領時に設定する（既定は未設定 = 削除可能）。
   */
  readonly legalHold?: boolean;
  /**
   * VC をどの RP へ・どの purpose で提示したかの履歴。`recordPresentation` が
   * 提示のたびに追記する。`revokeConsent` の `rpIdentifier` / `purpose` スコープはこの履歴を走査して
   * 対象 VC を解決する。既定は未設定（= 提示履歴なし）。
   */
  readonly presentedTo?: readonly PresentedToEntry[];
}

/**
 * Dashboard ログの 1 エントリ。
 *
 * `signature` は本エントリの正準 payload（`type` / `payload` / `recordedAt` / `prevHash`）に対する
 * コンパクト JWS（`header.payload.signature`）で、改ざん検知に用いる。`prevHash` は直前エントリの
 * signing-input の SHA-256（base64url）で、Merkle（ハッシュ）chain の連続性を担保する。
 */
export interface DashboardLogEntry {
  /** エントリ ID（storage キー・追記順のソートに用いる連番を含む）。 */
  readonly id: string;
  /** エントリ種別。 */
  readonly type: LogEntryType;
  /** 記録日時（ISO 8601）。 */
  readonly recordedAt: string;
  /** エントリ固有の内容（種別ごとに異なる。秘密情報は含めない）。 */
  readonly payload: Readonly<Record<string, unknown>>;
  /** 直前エントリの signing-input の SHA-256（base64url）。先頭エントリは `null`。 */
  readonly prevHash: string | null;
  /** 本エントリのコンパクト JWS 署名（`header.payload.signature`）。 */
  readonly signature: string;
}

/** `correctionRequest` エントリの payload（Art.16 訂正要求）。 */
export interface CorrectionRequestPayload {
  /** 訂正要求対象の VC ID。 */
  readonly vcId: string;
  /** 訂正要求の理由。 */
  readonly reason: string;
}

/**
 * 同意撤回のスコープ（GDPR Art.7(3) 同意撤回）。
 *
 * いずれのフィールドも任意だが、少なくとも 1 つを指定する必要がある（全フィールド未指定は
 * 撤回対象を特定できないため `GDPR_CONSENT_NOT_FOUND` エラーとする）。複数指定時は AND 条件で
 * 対象を絞り込む（例: 特定 RP かつ特定目的の同意のみを撤回）。
 */
export interface ConsentScope {
  /** 特定 RP に対する同意を撤回する（RP 識別子）。 */
  readonly rpIdentifier?: string;
  /** 特定目的の同意を撤回する。 */
  readonly purpose?: string;
  /** 特定 VC に対する同意を撤回する（VC ID）。 */
  readonly vcId?: string;
  /** 特定 Pseudonym に対する同意を撤回する。 */
  readonly pseudonym?: string;
}

/**
 * `consentRevoked` エントリの payload（Art.7(3) 同意撤回）。
 *
 * 撤回したスコープをそのまま記録する（Dashboard ログから撤回証跡を機械可読にたどれるようにする）。
 * 秘密情報は含まない（RP 識別子・目的・VC ID・Pseudonym はいずれも Dashboard で閲覧可能な情報）。
 */
export interface ConsentRevokedPayload {
  /** 撤回した同意のスコープ。 */
  readonly scope: ConsentScope;
}

/**
 * `credentialDeleted` エントリの payload（Art.17 忘れられる権利）。
 *
 * VC 本体は物理削除されるため、削除の事実のみを監査用の別ログパーティションに記録する。VC の内容・
 * 秘密情報は含めず、削除対象の VC ID のみを保持する（削除証跡を機械可読にたどれるようにする）。
 */
export interface CredentialDeletedPayload {
  /** 物理削除した VC の ID。 */
  readonly vcId: string;
}

/**
 * 個別 / フィルタ削除で物理削除した `dashboard-log/` エントリ 1 件分の構造的証跡。
 *
 * {@link LogEntryDeletedPayload} の `deletions` の要素。攻撃者によるセクション削除
 * と区別するため、削除したエントリが chain 上で持っていた `seq` / `prevHash` と、
 * 削除したエントリ自身の signing-input ハッシュ（次エントリの `prevHash` 照合に使う）を残す。
 * `verifyDashboardLogChain` はこの記録と矛盾なく説明できる欠損だけを `sequenceGap` から除外する
 * （{@link ../log-integrity/chain.js!DashboardLogDeletionRecords}）。
 */
export interface DeletedLogEntryRecord {
  /** 削除したエントリの連番（`seqToId` 形式の ID から取り出した数値）。 */
  readonly seq: number;
  /** 削除したエントリが保持していた `prevHash`（連番 0 なら `null`）。 */
  readonly prevHash: string | null;
  /** 削除したエントリの signing-input の SHA-256（base64url）。`signingInputHash` と同一計算。 */
  readonly entryHash: string;
}

/**
 * `logEntryDeleted` の payload。Art.17 に基づく個別削除・フィルタ削除を記録する。
 *
 * `DashboardLog.deleteLogEntry` / `deleteLogEntries` が 1 回の削除操作で物理削除した
 * `dashboard-log/` エントリすべての証跡をまとめて記録する。`credentialDeleted`（VC 単位の削除事実の
 * 監査）とは別の目的（chain 検証への入力）を持つため型を分ける。
 */
export interface LogEntryDeletedPayload {
  /** 本操作で物理削除した `dashboard-log/` エントリの証跡（追記順は問わない）。 */
  readonly deletions: readonly DeletedLogEntryRecord[];
}

/**
 * `unlock` エントリの payload。
 *
 * 施錠中は署名・暗号化（K4）の両方が使えないため直接追記できない。extension は解錠成立時点の
 * 日時をバッファ（`chrome.storage.session`）へ積み、次回解錠時に chain へ flush する
 * （`recordedAt` は flush 時刻になるため、実際に解錠した日時を `unlockedAt` として別に持つ）。
 */
export interface UnlockPayload {
  /** 解錠が成立した日時（ISO 8601）。 */
  readonly unlockedAt: string;
}

/**
 * `authFailure` エントリの payload。
 *
 * 解錠試行の失敗は定義上ウォレットが施錠されたままの状態で発生するため `unlock` と同じくバッファ経由で
 * 記録する。
 */
export interface AuthFailurePayload {
  /** 解錠試行が失敗した日時（ISO 8601）。 */
  readonly attemptedAt: string;
  /** 失敗した解錠方式。 */
  readonly method: 'password' | 'biometric';
}

/**
 * `/.well-known/dsr-endpoint` の発見メタデータ（Art.15–22）。
 *
 * データ主体の権利行使のための DSR (Data Subject Request) 受付エンドポイントの参照。DSR 対応 SLA は
 * Issuer / RP の運用責任範囲であり、SDK は本メタデータの発見（取得・パース）のみを提供する。
 */
export interface DsrEndpointMetadata {
  /** DSR を受け付けるエンドポイント（HTTPS URL、必須）。 */
  readonly dsrEndpoint: string;
  /** 対応するデータ主体の権利（例: `access` / `erasure` / `portability`）。任意。 */
  readonly supportedRights?: readonly string[];
  /** エクスポート等で対応するデータ形式（例: `application/json`）。任意。 */
  readonly formats?: readonly string[];
}

/**
 * `/.well-known/dpo-contact` の発見メタデータ（Art.37–39）。
 *
 * Data Protection Officer の連絡先。SDK 自体は DPO を任命せず、組込先の Issuer / RP / Wallet Provider が
 * 公開する連絡先を発見するのみ。連絡手段として `email` を必須とする（GDPR Art.37(7)）。
 */
export interface DpoContactMetadata {
  /** DPO の連絡先メールアドレス（必須）。 */
  readonly email: string;
  /** DPO の氏名 / 部署名。任意。 */
  readonly name?: string;
  /** DPO の電話番号。任意。 */
  readonly phone?: string;
  /** DPO の連絡先住所。任意。 */
  readonly address?: string;
  /** DPO 連絡窓口の Web URL（HTTPS）。任意。 */
  readonly url?: string;
}

/**
 * `transferWarning` エントリの payload（Cross-border Data Transfer、Art.44–50）。
 *
 * SDK が外部通信先（RP）のドメイン / Trusted List 属性から推定した国コードで EU / EEA 域外転送を
 * 検出したときに記録する（`transfer_warning` イベント）。RP アクセス検証の `crossBorderWarning`
 * フラグと国コード検出結果を機械可読に残し、Dashboard から越境転送の証跡をたどれるようにする。
 * 秘密情報は含めない（RP 識別子・国コード・origin はいずれも Dashboard で閲覧可能な公開情報）。
 */
export interface TransferWarningPayload {
  /** 転送先 RP の識別子（法人識別子。特定できない場合は空文字）。 */
  readonly rpIdentifier: string;
  /** 推定した RP 所在国の ISO 3166-1 alpha-2（不明時は空文字）。 */
  readonly country: string;
  /** RP サービス URI（国コード推定に用いた外部通信先。不明時は空文字）。 */
  readonly origin: string;
}

/**
 * Dashboard ログの一括削除（`purgeDashboardLog`）/ エクスポート（`exportDashboardLog`）で対象を
 * 絞り込むフィルタ（GDPR Art.17 削除権、Art.15 アクセス権）。
 *
 * すべてのフィールドは任意。複数指定時は AND 条件で対象を絞り込む（すべての条件を満たすエントリのみ対象）。
 * `filter` 自体を省略した場合はユーザー制御 Dashboard ログ（`dashboard-log/`）の全エントリが対象となる。
 * 監査用の Art.17 削除記録（`deletion-log/`）は常に対象外。
 */
export interface LogFilter {
  /** この ISO 8601 日時より古い（`recordedAt <` の）エントリのみを対象とする。 */
  readonly olderThan?: string;
  /** 指定した種別のいずれかに一致するエントリのみを対象とする。 */
  readonly types?: readonly LogEntryType[];
  /**
   * 特定 RP に関連するエントリのみを対象とする（RP 識別子）。payload 直下の `rpIdentifier`・`clientId`
   * （`presentation`）、または `scope.rpIdentifier`（`consentRevoked`）が正規化後に一致するエントリを対象とする。
   */
  readonly rpIdentifier?: string;
}
