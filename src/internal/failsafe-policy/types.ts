/**
 * Fail-safe ポリシー（Fail-open / Fail-closed の切替）で使う型定義。
 *
 * 実装（判定ロジック・時間上限）から型を分離し、issuer / credential など複数ドメインが循環 import
 * なしに参照できるようにする（`status-list-types.ts` と同じ分離方針）。
 *
 * セキュリティ上の注意:
 * - 監査レコードに URL・インデックス・ビット値・JWT を含めない。
 *   `verifier` / `vc_id` / `trace_id` は呼び出し側が用意した識別子（ハッシュ等）を
 *   そのまま渡す前提であり、SDK 側で URI 等から導出しない。
 */

/**
 * Fail-open を選択できる事象（FO-1〜FO-12）の ID。
 */
export type FailOpenId =
  | 'FO-1'
  | 'FO-2'
  | 'FO-3'
  | 'FO-4'
  | 'FO-5'
  | 'FO-6'
  | 'FO-7'
  | 'FO-8'
  | 'FO-9'
  | 'FO-10'
  | 'FO-11'
  | 'FO-12';

/**
 * Fail-safe 判定の重大度。
 *
 * - `deny`: fail-closed。呼び出し側は元の失敗をそのまま伝播する（拒否）。
 * - `warn`: fail-open。ユーザー同意と監査ログ記録を条件に警告付きで通過する。
 */
export type FailSafeSeverity = 'deny' | 'warn';

/**
 * SDK 利用者が事象 ID ごとに既定の Fail-open ポリシーを上書きするオプション。
 *
 * 常時拒否する事象は上書きできない。
 * - `suppressPrompt` を使う場合、同意事実を事前に記録する責務は SDK 利用者に移る。
 * - 監査ログ記録は省略不可（`escalate` / `suppressPrompt` のいずれでも省略できない）。
 */
export interface FailSafePolicy {
  /** 既定で Fail-open の事象を Fail-closed に格上げする ID の一覧。 */
  readonly escalate?: readonly FailOpenId[];
  /** Fail-open 時の UI プロンプトを抑制する ID の一覧（CI / バッチ処理用途）。 */
  readonly suppressPrompt?: readonly FailOpenId[];
  /** VC refresh 失敗時の既定挙動（FO-9）。 */
  readonly refreshFailure?: 'keep-old' | 'discard' | 'prompt';
  /** 非 LoA High Passkey プロバイダーを許容するか（FO-11、既定 false）。 */
  readonly allowSubstantialPasskey?: boolean;
}

/** 失敗事象に対する fail-safe 判定結果。 */
export interface FailSafeDecision {
  /** 判定対象の FO-ID。 */
  readonly policyEvent: FailOpenId;
  /** `deny`（fail-closed）か `warn`（fail-open）か。 */
  readonly severity: FailSafeSeverity;
  /** 監査ログに記録するイベント名。 */
  readonly auditEvent: string;
  /** UI 警告とユーザー同意を要求するか。 */
  readonly promptRequired: boolean;
}

/** Fail-open で通過した事実を検証結果へ添える警告。 */
export interface FailSafeWarning {
  /** 通過を許した FO-ID。 */
  readonly policyEvent: FailOpenId;
  /** 監査ログに記録したイベント名。 */
  readonly auditEvent: string;
}

/**
 * 監査レコードへ付与する相関情報。
 *
 * 値は呼び出し側が用意した識別子（RP 識別子のハッシュ・Wallet 内 VC ID・Observability の相関 ID）を
 * そのまま渡す。SDK は URI 等から導出しない。
 */
export interface FailSafeAuditContext {
  /** RP 識別子（ハッシュ）。 */
  readonly verifier?: string;
  /** 対象 VC の ID（Wallet 内識別子）。 */
  readonly vc_id?: string;
  /** Observability の相関 ID。 */
  readonly trace_id?: string;
}

/**
 * Fail-open 判定の監査レコード。
 *
 * フィールド名は snake_case とする（Dashboard ログの項目名と 1:1 対応）。
 * 同意が得られなかった場合（`user_consent: 'rejected'`）も記録対象で、省略できない。
 */
export interface FailSafeAuditRecord {
  /** 事象 ID（例: `FO-1`）。 */
  readonly policy_event: FailOpenId;
  /** 監査イベント名（例: `status_check_unreachable`）。 */
  readonly audit_event: string;
  /** ユーザー同意の結果。 */
  readonly user_consent: 'accepted' | 'rejected';
  /** SDK 利用者の `FailSafePolicy` 内容（未指定なら空オブジェクト）。 */
  readonly override: FailSafePolicy;
  /** RP 識別子（ハッシュ、任意）。 */
  readonly verifier?: string;
  /** 対象 VC の ID（Wallet 内識別子、任意）。 */
  readonly vc_id?: string;
  /** Observability の相関 ID（任意）。 */
  readonly trace_id?: string;
}
