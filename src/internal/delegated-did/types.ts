/**
 * DelegatedDID の型定義。
 *
 * 自身が controller として指定されている外部 DID（例: 企業 DID）の情報。委任 DID の VC 発行・提示
 * 権限そのもの（delegation grant / subject binding）とは別物で、「どの DID の controller を自分が
 * 務めているか」を追跡する台帳の役割を持つ。
 *
 * 本モジュールは型のみを提供し、永続化は `delegated-did-store.ts` が担う。
 *
 * セキュリティ上の注意:
 * - DID / 表示名など公開情報のみを保持する。鍵・seed・PIN 等の秘密は一切含めない。
 */

/** DelegatedDID のステータス。 */
export type DelegationStatus = 'active' | 'revoked' | 'unknown';

/** 委任 DID。`did` が storage 上の主キー。 */
export interface DelegatedDID {
  /** 委任された DID。 */
  readonly did: string;
  /** コントローラーの DID（自分）。 */
  readonly controllerDID: string;
  /** 表示名（例: "株式会社○○"）。 */
  readonly name: string;
  /** 最後に DID ドキュメントを解決した日時（ISO 8601）。 */
  readonly resolvedAt: string;
  /** ステータス。 */
  readonly status: DelegationStatus;
}

/** `DelegatedDIDStore.upsert` の入力。 */
export interface UpsertDelegatedDIDOptions {
  /** 委任された DID。 */
  readonly did: string;
  /** コントローラーの DID（自分）。 */
  readonly controllerDID: string;
  /** 表示名。 */
  readonly name: string;
  /** ステータス。省略時は `"unknown"`。 */
  readonly status?: DelegationStatus;
  /** 最後に DID ドキュメントを解決した日時（ISO 8601）。省略時は現在時刻。 */
  readonly resolvedAt?: string;
}
