/**
 * SD-JWT VC Type Metadata の型定義と定数。
 *
 * 準拠規格: draft-ietf-oauth-sd-jwt-vc §6（SD-JWT VC Type Metadata）。
 *
 * `vct` が HTTPS URL の場合、その URL は VC 種別のスキーマ・display・claims 定義を返す
 * Type Metadata 文書を指す。本モジュール群は、その取得・検証・`extends` 継承解決・キャッシュを担う。
 */

import type {
  FailOpenWindow,
  FailSafeAuditContext,
  FailSafeAuditRecord,
  FailSafeDecision,
  FailSafePolicy,
} from '../../../failsafe-policy/index.js';
import type { FetchLike } from '../../../fetch-di.js';
import type { PresentationWorkBudget } from '../../../primitives/presentation-work-budget.js';
import type { JsonSchema, SchemaFailSafeResult } from '../../json-schema/index.js';
import { SCHEMA_FETCH_TIMEOUT_MS } from '../../json-schema/index.js';
import type { TypeMetadataCache } from './cache.js';

/** Type Metadata キャッシュの既定 TTL（ミリ秒、5 分）。`chain/` の TTL 方針に揃える。 */
export const TYPE_METADATA_CACHE_TTL_MS = 5 * 60 * 1000;

/** `extends` チェーンを辿る最大段数（循環・過大なチェーンの防御）。 */
export const MAX_EXTENDS_DEPTH = 10;

/** 1 つの Type Metadata 文書が持てる `claims` の最大要素数（DCQL の `MAX_DCQL_CLAIMS_PER_CREDENTIAL` と同値）。 */
export const MAX_TYPE_METADATA_CLAIMS = 128;

/** 1 つの Type Metadata 文書が持てる `display` の最大要素数（言語別ラベル数）。 */
export const MAX_TYPE_METADATA_DISPLAY = 64;

/**
 * Type Metadata 取得のタイムアウト（ミリ秒）。
 *
 * 実際の適用は共有プリミティブ（`json-schema/fetch-document.ts`）が行うため、値が二重定義で
 * 乖離しないよう `SCHEMA_FETCH_TIMEOUT_MS` を別名として公開する。
 */
export const TYPE_METADATA_TIMEOUT_MS = SCHEMA_FETCH_TIMEOUT_MS;

/**
 * SD-JWT VC Type Metadata 文書（draft-ietf-oauth-sd-jwt-vc §6.1）。
 *
 * 未知のメンバは将来拡張のためそのまま保持する（`readonly [key: string]: unknown`）。
 */
export interface SdJwtTypeMetadata {
  /** この Type Metadata が定義する VC 種別識別子。取得元 URL と一致することを検証する。 */
  readonly vct: string;
  /** 人間可読な名称。 */
  readonly name?: string;
  /** 人間可読な説明。 */
  readonly description?: string;
  /** 継承元 Type Metadata の URL。 */
  readonly extends?: string;
  /**
   * 継承元文書の Subresource Integrity 値（`extends#integrity`）。
   *
   * SDK は SRI を検証できないため、宣言されていれば取得時に 3061 で拒否する（`fetch.ts`）。
   * 型として残すのは、draft §6.1 のメンバであることを示し受理集合の判断根拠を明示するため。
   */
  readonly 'extends#integrity'?: string;
  /** クレーム構造を定義する JSON Schema（インライン）。`schema_uri` と排他。 */
  readonly schema?: JsonSchema;
  /** クレーム構造を定義する JSON Schema の URL。`schema` と排他。 */
  readonly schema_uri?: string;
  /** スキーマ文書の Subresource Integrity 値（`schema_uri#integrity`）。扱いは `extends#integrity` と同じ。 */
  readonly 'schema_uri#integrity'?: string;
  /** 表示メタデータ（言語別のラベル・ロゴ等）。 */
  readonly display?: readonly unknown[];
  /** クレーム個別のメタデータ（表示名・選択的開示可否等）。 */
  readonly claims?: readonly unknown[];
  /** 将来拡張のための未知メンバ。 */
  readonly [key: string]: unknown;
}

/** ネットワーク取得を注入するための依存（テストは実 fetch を使わずに注入する）。 */
export interface TypeMetadataDependencies {
  /**
   * `fetch` 互換の取得関数。未指定ならグローバル `fetch` を使う。
   *
   * Type Metadata の URL は VC の `vct`（Issuer 由来 = 攻撃者が影響し得る値）であるため、
   * 実装側で HTTPS 限定・リダイレクト先の HTTPS 維持・Content-Type を検証する。
   *
   * 型は `typeof fetch` ではなく {@link FetchLike}（横断 `fetch-di.ts`）である。`typeof fetch` は
   * ランタイム固有の拡張（Bun の `preconnect` 等）まで要求するため、`class Deps { fetchImpl() {…} }`
   * のような正当な注入実装が代入できない。
   */
  readonly fetchImpl?: FetchLike;
}

/**
 * `resolveTypeMetadata` / `validateClaimsAgainstTypeMetadata` のオプション。
 *
 * `credentialSchema` 経路の `ValidateCredentialSchemaOptions` と同じ形に揃える（別エコシステムだが
 * fail-safe の落とし方は共通のため）。
 */
export interface ResolveTypeMetadataOptions extends TypeMetadataDependencies {
  /**
   * 取得する文書の件数・総バイト数を数える共有予算（`verifyPresentation` と同じ `PresentationWorkBudget` を
   * 渡すと VP 全体で消費する）。`resolveTypeMetadata` / `validateClaimsAgainstTypeMetadata` は省略時に
   * 1 回の解決専用の予算を作る。超過は `3061`（`reason: "metadata_too_large"`）で、fail-open しない。
   */
  readonly workBudget?: PresentationWorkBudget;
  /** Type Metadata 文書のキャッシュ。未指定ならモジュール既定の共有キャッシュを使う。 */
  readonly metadataCache?: TypeMetadataCache<SdJwtTypeMetadata>;
  /** JSON Schema 文書のキャッシュ。未指定ならモジュール既定の共有キャッシュを使う。 */
  readonly schemaCache?: TypeMetadataCache<JsonSchema>;
  /** 現在時刻（エポックミリ秒）。テストの決定性のため注入可能。既定は `Date.now()`。 */
  readonly nowMs?: number;
  /**
   * 既定の fail-safe ポリシーに対する override。
   *
   * `escalate: ['FO-3']` で取得失敗（3060）を例外として伝播させ、`escalate: ['FO-4']` で
   * 任意属性のみの違反を `valid: false` に格上げする。対象は事象 ID の列挙で指定する。
   * 構造不正（3061）はこの指定に関わらず常に例外になる。
   */
  readonly failSafePolicy?: FailSafePolicy;
  /**
   * UI 警告を出しユーザー同意を取るコールバック。
   *
   * 未指定なら同意を取る手段が無いため FO-3 / FO-4 の Fail-open は成立せず、取得失敗（3060）は
   * そのまま伝播し、任意属性のみの違反も `valid: false` になる（既定は Fail-closed）。
   */
  readonly requestConsent?: (decision: FailSafeDecision) => boolean | Promise<boolean>;
  /**
   * Fail-open 判定の監査ログ記録先。同意・不同意のいずれでも呼ばれる。
   *
   * 未指定の場合は監査記録を残せないため、警告による通過を許可しない。
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

/**
 * `extends` チェーン上の 1 文書が宣言したスキーマ（`schema` か `schema_uri` のどちらか）。
 *
 * `mergeMetadata` は `schema` / `schema_uri` を子が親を丸ごと置き換える浅いマージのため、マージ後の
 * `metadata` からは祖先のスキーマが消える。SD-JWT VC §6.5.2 は祖先のスキーマも同じ VC に対して評価する
 * ことを MUST とするので、文書ごとの宣言をこの形で別に保持する。
 */
export interface TypeMetadataSchemaSource {
  /** インラインの JSON Schema。 */
  readonly schema?: JsonSchema;
  /** スキーマ文書の URL。 */
  readonly schema_uri?: string;
}

/**
 * `extends` を解決してマージ済みの Type Metadata。
 *
 * `metadata` は「継承元 → 継承先」の順に浅くマージした結果で、同名メンバは**継承先（子）が優先**する。
 * したがって `metadata.schema` / `metadata.schema_uri` は**起点（子）が持つ宣言**であり、検証には使えない
 * （祖先のスキーマが落ちる）。検証には `schemas` を使う。
 * `chain` は解決に用いた URL を子から親の順に並べたもので、監査・デバッグ用。
 */
export interface ResolvedTypeMetadata {
  /** マージ済み Type Metadata。 */
  readonly metadata: SdJwtTypeMetadata;
  /** 解決に辿った `vct` URL（先頭が起点、以降が `extends` 祖先）。 */
  readonly chain: readonly string[];
  /**
   * チェーン上の各文書が宣言したスキーマ（最も遠い祖先 → 起点の順）。スキーマを持たない文書は含めない。
   * 全スキーマを同じクレームに対して評価し（`allOf` 相当）、1 つでも違反すれば不適合とする。
   */
  readonly schemas: readonly TypeMetadataSchemaSource[];
}

/**
 * Type Metadata に基づくクレーム構造検証の結果。
 *
 * W3C `credentialSchema` の検証と共通の {@link SchemaFailSafeResult}。
 * 警告による通過を許可した場合、取得失敗（FO-3）は `schemaAvailable: false` と `warnings`、
 * 任意属性のみの違反（FO-4）は `valid: true` と `warnings` を返し、違反内容を `errors` に残す。
 * 必須属性違反は `valid: false` になり、該当するエラーは `required: true` を持つ。
 *
 * 形が両経路で同一のためフィールドは共有型側にのみ定義し、ここでは別名として公開する
 * （二重定義による乖離を避ける）。
 */
export type TypeMetadataValidationResult = SchemaFailSafeResult;
