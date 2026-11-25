/**
 * VC JSON Schema 検証（`credentialSchema`）の型と定数。
 *
 * 準拠規格: [W3C Verifiable Credentials JSON Schema](https://www.w3.org/TR/vc-json-schema/)。
 *
 * 本経路は SD-JWT VC の Type Metadata 経路とは**別エコシステム**であり、
 * claim を混同しない。共有するのは HTTPS 取得プリミティブと JSON Schema 検証器のみ。
 */

import type {
  FailOpenWindow,
  FailSafeAuditContext,
  FailSafeAuditRecord,
  FailSafeDecision,
  FailSafePolicy,
} from '../../../failsafe-policy/index.js';
import type { SchemaFetchDependencies } from '../../json-schema/index.js';
import type { CredentialSchemaCache } from './cache.js';

/** スキーマ文書キャッシュの既定 TTL（ミリ秒、5 分）。Type Metadata 経路の TTL 方針に揃える。 */
export const CREDENTIAL_SCHEMA_CACHE_TTL_MS = 5 * 60 * 1000;

/**
 * JSON Schema による検証対象とみなす `credentialSchema.type`。
 *
 * `JsonSchema`（vc-json-schema §4.1）は「`id` が JSON Schema 文書を指す」形式で、取得した JSON を
 * そのままスキーマとして扱える。
 *
 * **`JsonSchemaCredential`（§4.2）は受理しない。** こちらは「`id` がスキーマを内包する VC を指す」
 * 形式で、取得できるのは JSON Schema ではなく VC 文書である。VC の署名検証と
 * `credentialSubject.jsonSchema` の取り出しが未対応の現状でその VC 文書をスキーマとして扱うと、
 * VC のルート（`type` 配列など）がスキーマ定義と解釈され**偽の型違反**を生む。受理集合から外して
 * 3016（`SCHEMA_NOT_SPECIFIED` = 検証できるスキーマの指定なし）に倒し、検証したつもりの穴も
 * 偽の違反も作らない。
 */
export const JSON_SCHEMA_CREDENTIAL_TYPES: ReadonlySet<string> = new Set(['JsonSchema']);

/**
 * `validateCredentialSchema` / `validateClaimsAgainstCredentialSchema` のオプション
 * （`ResolveTypeMetadataOptions` と同じ形に揃える）。
 */
export interface ValidateCredentialSchemaOptions extends SchemaFetchDependencies {
  /** スキーマ文書のキャッシュ。未指定ならモジュール既定の共有キャッシュを使う。 */
  readonly schemaCache?: CredentialSchemaCache;
  /** 現在時刻（エポックミリ秒）。テストの決定性のため注入可能。既定は `Date.now()`。 */
  readonly nowMs?: number;
  /**
   * 既定の fail-safe ポリシーに対する override。
   *
   * `escalate: ['FO-3']` でスキーマを取得 / 解決できない事象（3015 / 3016）を例外として伝播させ、
   * `escalate: ['FO-4']` で任意属性のみの違反を `valid: false` に格上げする。boolean での
   * 一括切替は持たず、事象 ID の列挙で指定する。
   */
  readonly failSafePolicy?: FailSafePolicy;
  /**
   * UI 警告を出しユーザー同意を取るコールバック。
   *
   * 未指定なら同意を取る手段が無いため FO-3 / FO-4 の Fail-open は成立せず、取得失敗（3015）は
   * そのまま伝播し、任意属性のみの違反も `valid: false` になる（既定は Fail-closed）。
   */
  readonly requestConsent?: (decision: FailSafeDecision) => boolean | Promise<boolean>;
  /**
   * Fail-open 判定の監査ログ記録先。同意・不同意のいずれでも呼ばれる。
   *
   * 未指定なら監査記録を残せないため、Fail-open は成立しない。
   */
  readonly onPolicyEvent?: (record: FailSafeAuditRecord) => void | Promise<void>;
  /** 監査レコードへ付与する相関情報。 */
  readonly auditContext?: FailSafeAuditContext;
  /**
   * Fail-open の時間上限を数えるウィンドウ。
   *
   * **プロセス共有の既定値は無い**。未指定なら FO-3 / FO-4 の
   * Fail-open は成立しない（Fail-closed。時間上限を計測できないため、同意コールバック /
   * 監査記録先が無い場合と同じ扱い）。インスタンスへ閉じ込めたウィンドウを使い回したい場合は
   * `createSchemaValidator`（`schema-validation/factory.ts`）を使う。
   */
  readonly failOpenWindow?: FailOpenWindow;
}
