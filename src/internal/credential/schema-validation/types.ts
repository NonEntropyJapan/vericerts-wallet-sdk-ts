/**
 * スキーマ検証経路の自動判定（ディスパッチャ）の型定義。
 *
 * 2 つの経路は**別エコシステム**であり、`credentialSchema` と `vct` の claim を相互に流用しない。
 * 共有するのは HTTPS 取得プリミティブ・JSON Schema 検証器・fail-safe の結果型のみで、本モジュールは
 * 「呼び出し側に経路を選ばせない」ためのディスパッチ層だけを足す。
 */

import type {
  FailSafeAuditContext,
  FailSafeAuditRecord,
  FailSafeDecision,
  FailSafePolicy,
} from '../../failsafe-policy/index.js';
import type { SchemaFailSafeResult, SchemaFetchDependencies } from '../json-schema/index.js';
import type { ResolveTypeMetadataOptions } from '../sdjwt/type-metadata/index.js';
import type { VerifiedSdJwt } from '../sdjwt/verify.js';
import type { ValidateCredentialSchemaOptions } from '../vc/credential-schema/index.js';
import type { VerifiableCredential } from '../vc/vc.js';

/**
 * 検証に用いた経路。
 *
 * - `sd-jwt-vc-type-metadata`: `vct` の Type Metadataで検証した。
 * - `w3c-vc-credential-schema`: `credentialSchema` の JSON Schemaで検証した。
 * - `both`: **両形式のシグナルを併せ持つ**入力を、どちらか一方に倒さず**両経路で検証**した
 *   （結果は合成する）。片方のシグナルを足すだけでもう片方の検証を回避させないための扱い。
 * - `none`: どちらの形式とも判定できず**検証していない**（`schemaAvailable: false` を伴う）。
 */
export type SchemaValidationRoute =
  | 'sd-jwt-vc-type-metadata'
  | 'w3c-vc-credential-schema'
  | 'both'
  | 'none';

/**
 * ディスパッチャが検証できるクレデンシャル。
 *
 * SD-JWT VC 側は `vct` と `claims` があれば足りるため、`VerifiedSdJwt` 全体ではなく必要な 2 つの
 * メンバのみを要求する（KB 検証結果や `cnf` はスキーマ検証に無関係なため）。
 */
export type SchemaValidatableCredential =
  | VerifiableCredential
  | Pick<VerifiedSdJwt, 'claims' | 'vct'>;

/** 両経路へ透過的に渡す共通オプション。 */
export interface SharedSchemaValidationOptions extends SchemaFetchDependencies {
  /** 現在時刻（エポックミリ秒）。テストの決定性のため注入可能。既定は `Date.now()`。 */
  readonly nowMs?: number;
  /**
   * 既定の fail-safe ポリシーに対する override。選ばれた経路へ透過する。
   *
   * `escalate: ['FO-3']` でスキーマを取得 / 解決できない事象（3015 / 3016 / 3060）を例外として
   * 伝播させ、`escalate: ['FO-4']` で任意属性のみの違反を `valid: false` に格上げする。
   * boolean での一括切替は持たない。Type Metadata の構造不正（3061）にはこのポリシーを適用しないため、本指定に
   * 関わらず常に例外として伝播する。
   */
  readonly failSafePolicy?: FailSafePolicy;
  /**
   * UI 警告を出しユーザー同意を取るコールバック。
   *
   * 未指定なら同意を取る手段が無いため FO-3 / FO-4 の Fail-open は成立せず、取得失敗はそのまま
   * 伝播し、任意属性違反は `valid: false` になる（既定は Fail-closed）。
   */
  readonly requestConsent?: (decision: FailSafeDecision) => boolean | Promise<boolean>;
  /**
   * Fail-open 判定の監査ログ記録先。同意・不同意のいずれでも呼ばれる。
   *
   * 監査記録先を省略すると Fail-closed になる。
   */
  readonly onPolicyEvent?: (record: FailSafeAuditRecord) => void | Promise<void>;
  /** 監査レコードへ付与する相関情報。 */
  readonly auditContext?: FailSafeAuditContext;
}

/** 経路別オプションから共通分を除いた残り（キャッシュ等の経路固有メンバのみ）。 */
type RouteSpecific<T> = Omit<T, keyof SharedSchemaValidationOptions>;

/**
 * {@link SchemaValidationRoute} 判定を伴う検証のオプション。
 *
 * 共通メンバ（`fetchImpl` / `nowMs` / `failSafePolicy` と fail-safe の同意・監査オプション）は上位に
 * 1 つだけ置き、選ばれた経路へそのまま透過させる。経路固有のキャッシュは両経路で型が異なる
 * （`TypeMetadataCache` と `CredentialSchemaCache`）ため、交差型にせず経路ごとの入れ子で受け取る。
 * Fail-open の計時ウィンドウ（`failOpenWindow`）も経路ごとに独立させるため共通側には置かない。
 */
export interface RoutedSchemaValidationOptions extends SharedSchemaValidationOptions {
  /** Type Metadata 経路にのみ渡す追加オプション（`metadataCache` / `schemaCache`）。 */
  readonly typeMetadataOptions?: RouteSpecific<ResolveTypeMetadataOptions>;
  /** `credentialSchema` 経路にのみ渡す追加オプション（`schemaCache`）。 */
  readonly credentialSchemaOptions?: RouteSpecific<ValidateCredentialSchemaOptions>;
}

/**
 * 経路情報を添えたスキーマ検証結果。
 *
 * 判定結果の形は両経路で同一のため {@link SchemaFailSafeResult} をそのまま拡張し、
 * 「どちらのエコシステムで検証したか（あるいは検証していないか）」だけを `route` で足す。
 * 監査ログで FO-3 / FO-4 の警告がどちらの経路由来かを区別するために使う。
 */
export interface RoutedSchemaValidationResult extends SchemaFailSafeResult {
  /** 実際に用いた検証経路。`none` は検証していないことを表す。 */
  readonly route: SchemaValidationRoute;
}
