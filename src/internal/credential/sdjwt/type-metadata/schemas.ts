/**
 * `extends` チェーン上の全スキーマによるクレーム検証（draft-ietf-oauth-sd-jwt-vc §6.5.2）。
 *
 * `extends` を持つ型では「拡張元の型のスキーマも同じ VC に対して評価し、チェーン上のいずれかで失敗したら
 * VC を拒否しなければならない（MUST）」。以前はマージ後の単一スキーマ（子が親を置換）だけを評価していたため、
 * 派生型の作者（= 発行者）が自分の Type Metadata に `schema: {}` を書くだけで基底型の必須属性・型制約を
 * 迂回できた。ここでは各文書のスキーマを個別に取得し、`allOf` 相当で全件を評価して違反を連結する。
 */

import { ErrorCodes, VericertsError } from '../../../errors.js';
import type { PresentationWorkBudget } from '../../../primitives/presentation-work-budget.js';
import { spendWork } from '../../../primitives/presentation-work-budget.js';
import { nonObjectPrototypeProperty, ownProperty } from '../../../prototype-safety/own-property.js';
import type { JsonSchema, SchemaError } from '../../json-schema/index.js';
import { validateAgainstSchema } from '../../json-schema/index.js';
import {
  applySchemaViolations,
  clearFailOpenWindow,
  credentialFingerprint,
  schemaFetchFailedResult,
} from '../../schema-validation/fail-safe.js';
import { TypeMetadataCache } from './cache.js';
import { fetchSchemaDocument } from './fetch.js';
import type {
  ResolveTypeMetadataOptions,
  SdJwtTypeMetadata,
  TypeMetadataSchemaSource,
  TypeMetadataValidationResult,
} from './types.js';

/** モジュール既定の共有スキーマキャッシュ。 */
const defaultSchemaCache = new TypeMetadataCache<JsonSchema>();

/**
 * 文書列（起点 → 祖先の順）から、スキーマを宣言した文書のスキーマ宣言を祖先 → 起点の順で集める。
 *
 * 両メンバは own 限定で読む。文書は `null` プロトタイプ（取得文書）のため現時点では冗長だが、読み取り
 * 位置に規律を残す多層防御である。`schema` と `schema_uri` の併記は `schema` を優先する
 * （従来の `loadSchema` と同じ）。
 */
export function collectSchemaSources(
  documents: readonly SdJwtTypeMetadata[],
): readonly TypeMetadataSchemaSource[] {
  const sources: TypeMetadataSchemaSource[] = [];
  for (let i = documents.length - 1; i >= 0; i -= 1) {
    const document = documents[i] as SdJwtTypeMetadata;
    const schema = ownProperty<JsonSchema>(document, 'schema');
    if (schema !== undefined) {
      sources.push({ schema });
      continue;
    }
    const schemaUri = ownProperty<string>(document, 'schema_uri');
    if (schemaUri !== undefined) {
      sources.push({ schema_uri: schemaUri });
    }
  }
  return sources;
}

/** 1 つのスキーマ宣言を実体に解決する（`schema_uri` はキャッシュ経由で取得）。 */
async function loadSchema(
  source: TypeMetadataSchemaSource,
  options: ResolveTypeMetadataOptions,
  now: number,
  budget: PresentationWorkBudget,
): Promise<JsonSchema> {
  const inline = ownProperty<JsonSchema>(source, 'schema');
  if (inline !== undefined) {
    return inline;
  }
  // `schema_uri` 文書も `extends` 文書と同じ総量予算で数える（チェーン長 × 文書サイズの積にしない）。
  spendWork(budget, 'metadataDocuments');
  const schemaUri = ownProperty<string>(source, 'schema_uri') as string;
  const cache =
    nonObjectPrototypeProperty<TypeMetadataCache<JsonSchema>>(options, 'schemaCache') ??
    defaultSchemaCache;
  const cached = cache.get(schemaUri, now);
  if (cached !== undefined) {
    return cached;
  }
  const schema = await fetchSchemaDocument(schemaUri, options, budget);
  cache.set(schemaUri, schema, now);
  return schema;
}

/**
 * チェーン上の全スキーマで `claims` を検証する。
 *
 * - スキーマ宣言が 0 件: Type Metadata は構造制約を持たないので `schemaAvailable: false` で通す。
 * - 取得失敗（3060）は宣言単位で FO-3 のゲートに掛ける（`schema_uri` ごとの資源キーで計時）。通過を
 *   許されなければ元の例外を投げる（Fail-closed）。通過を許された宣言は「検証していない」ので
 *   `schemaAvailable: false` と FO-3 の監査キーを結果へ残し、**残りの宣言は引き続き評価する**。
 * - 取得できた全スキーマの違反を連結し、FO-4（任意属性のみの違反）は連結結果に対して 1 回だけ適用する。
 *   必須属性違反が 1 つでもあれば（どの型のスキーマ由来でも）`valid: false`。
 *
 * @param sources `collectSchemaSources` の結果（祖先 → 起点）。
 * @param claims 検証対象のクレーム。
 * @param vctResourceKey インライン宣言の FO-4 キー・FO-3 計時に使う `vct` チェーンの資源キー。
 * @param now 現在時刻（エポックミリ秒）。
 * @param options キャッシュ・`fetchImpl`・fail-safe override。
 * @param budget `resolveTypeMetadata` と共有する文書数・バイト数の予算。
 */
export async function validateAgainstChainSchemas(
  sources: readonly TypeMetadataSchemaSource[],
  claims: Readonly<Record<string, unknown>>,
  vctResourceKey: string,
  now: number,
  options: ResolveTypeMetadataOptions,
  budget: PresentationWorkBudget,
): Promise<TypeMetadataValidationResult> {
  if (sources.length === 0) {
    return { valid: true, schemaAvailable: false, warnings: [] };
  }
  const nowSeconds = Math.floor(now / 1000);
  const errors: SchemaError[] = [];
  const fetchFailedWarnings: string[] = [];
  const resourceKeys: string[] = [];
  let evaluated = 0;

  for (const source of sources) {
    // `schema_uri` から取得する場合はその URL 自身で計時する（`vct` 起因の失敗と区別するため）。
    const resourceKey =
      source.schema_uri === undefined ? vctResourceKey : `sdjwt-schema:${source.schema_uri}`;
    let schema: JsonSchema;
    try {
      schema = await loadSchema(source, options, now, budget);
    } catch (e) {
      if (e instanceof VericertsError && e.code === ErrorCodes.TYPE_METADATA_FETCH_FAILED) {
        const gated = await schemaFetchFailedResult(resourceKey, nowSeconds, options);
        if (gated !== undefined) {
          fetchFailedWarnings.push(...gated.warnings);
          continue;
        }
      }
      throw e;
    }
    // スキーマ資源の取得に成功した時点で FO-3 側の資源キーを破棄する。
    clearFailOpenWindow(resourceKey, options);
    resourceKeys.push(resourceKey);
    evaluated += 1;
    const result = validateAgainstSchema(schema, claims);
    for (const error of result.errors ?? []) {
      errors.push(error);
    }
  }

  if (evaluated === 0) {
    // 全宣言の取得に失敗し、すべて FO-3 で通過を許された（検証していない）。
    return { valid: true, schemaAvailable: false, warnings: fetchFailedWarnings };
  }

  // FO-4 の時間上限は資源キーにクレームの指紋を連結してクレデンシャル単位で管理する。
  // 複数スキーマを 1 つの結果に畳むため、評価した全資源キーを連結して 1 本のキーにする。
  const violationKey = `${[...new Set(resourceKeys)].join('|')}#${credentialFingerprint(claims)}`;
  const applied = await applySchemaViolations(
    violationKey,
    nowSeconds,
    errors.length === 0 ? { valid: true } : { valid: false, errors },
    options,
  );
  if (fetchFailedWarnings.length === 0) {
    return applied;
  }
  return {
    ...applied,
    schemaAvailable: false,
    warnings: [...fetchFailedWarnings, ...applied.warnings],
  };
}
