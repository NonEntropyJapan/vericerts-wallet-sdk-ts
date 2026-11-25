/**
 * TrustedIssuerList / TrustedIssuerEntry の型定義。
 *
 * [W3C CCG Verifiable Issuers and Verifiers v0.2](https://w3c-ccg.github.io/verifiable-issuers-verifiers/)
 * ドラフトに準拠した Trusted Issuer List（TIL）データ。手動追加・W3C CCG TSLv1 形式のインポート・
 * URL 購読のいずれで取り込んだ発行者も、1 つの `TrustedIssuerList.trustedIssuers` 配下に集約する。
 *
 * 本モジュールは型のみを提供し、永続化は `trusted-issuer-list-store.ts` が担う。
 *
 * セキュリティ上の注意:
 * - Issuer DID / 表示名など公開情報のみを保持する。鍵・seed・PIN 等の秘密は一切含めない。
 */

/** TrustedIssuerList に登録する発行者のエントリ。 */
export interface TrustedIssuerEntry {
  /** Issuer DID。 */
  readonly id: string;
  /** 表示名。 */
  readonly name: string;
  /** 対応 VC 種別（省略時は全種別を対象とみなす）。 */
  readonly credentialTypes?: string[];
  /** 信頼開始日（ISO 8601）。省略時は制約なし。 */
  readonly validFrom?: string;
  /** 信頼終了日（ISO 8601）。省略時は制約なし。 */
  readonly validUntil?: string;
  /** 登録元（`"ebsi"` / `"custom"` / 購読元 URL 文字列）。 */
  readonly source?: string;
}

/** Trusted Issuer List 本体。 */
export interface TrustedIssuerList {
  /** リスト識別子（UUID）。 */
  readonly id: string;
  /** 固定: `"TrustedIssuerList"`。 */
  readonly type: 'TrustedIssuerList';
  /** 固定: `"TSLv1"`。 */
  readonly version: 'TSLv1';
  /** リスト管理者の DID。 */
  readonly listOperator: string;
  /** リスト表示名。 */
  readonly listName: string;
  /** 発行日時（ISO 8601）。 */
  readonly issuedAt: string;
  /** 次回更新予定日時（ISO 8601）。 */
  readonly nextUpdate?: string;
  /** 購読元 URL（購読時のみ）。 */
  readonly sourceUrl?: string;
  /** 購読間隔（ミリ秒）。 */
  readonly intervalMs?: number;
  /** リストに含まれる発行者エントリ。 */
  readonly trustedIssuers: TrustedIssuerEntry[];
}

/** `TrustedIssuerListStore.createList` の入力。 */
export interface CreateTrustedIssuerListOptions {
  /** リスト識別子。省略時は採番する。 */
  readonly id?: string;
  /** リスト管理者の DID。 */
  readonly listOperator: string;
  /** リスト表示名。 */
  readonly listName: string;
  /** 次回更新予定日時（ISO 8601）。 */
  readonly nextUpdate?: string;
  /** 購読元 URL（購読時のみ）。 */
  readonly sourceUrl?: string;
  /** 購読間隔（ミリ秒）。 */
  readonly intervalMs?: number;
  /** 初期発行者エントリ（省略時は空配列）。 */
  readonly trustedIssuers?: TrustedIssuerEntry[];
}

/** `isTrustedIssuer` の評価オプション。 */
export interface IsTrustedIssuerOptions {
  /** 対応 VC 種別で絞り込む（エントリの `credentialTypes` が省略されていれば無条件に一致）。 */
  readonly credentialType?: string;
  /** 有効性を判定する基準時刻（既定は現在時刻）。 */
  readonly at?: Date;
}
