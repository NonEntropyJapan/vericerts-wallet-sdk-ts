/**
 * Type Metadata / JSON Schema 文書の取得（HTTPS + タイムアウト + 構造検証）。
 *
 * HTTPS 取得は
 * `credential/json-schema/fetch-document.ts` の共有プリミティブに委譲する
 * （HTTPS 限定・`fetchImpl` の DI・リダイレクト先の HTTPS 維持確認・JSON Content-Type 必須・
 * 本文 1 MiB 上限・`cause` を渡さない正規化）。本ファイルは Type Metadata 固有の
 * 構造検証（`vct` 一致・`schema` / `schema_uri` 排他・`claims` / `display` の配列性・
 * 検証できない `#integrity` の拒否）に専念する。
 *
 * セキュリティ上の注意:
 * - 取得元 URL は VC の `vct`（Issuer 由来 = 攻撃者が影響し得る値）。共有プリミティブ側で
 *   HTTPS 限定・リダイレクト先の HTTPS 維持を検証する（SSRF / 平文降格の防止）。
 * - URL・レスポンス本文を例外メッセージ・`context`・`cause` に含めない。
 */

import { ErrorCodes, VericertsError } from '../../../errors.js';
import { MAX_DOCUMENT_BYTES } from '../../../http/body-limit.js';
import type { PresentationWorkBudget } from '../../../primitives/presentation-work-budget.js';
import {
  remainingWork,
  spendWork,
  workBudgetExceeded,
} from '../../../primitives/presentation-work-budget.js';
import type { JsonSchema } from '../../json-schema/index.js';
import {
  assertNoUnverifiableIntegrity,
  fetchSchemaJson,
  isHttpsUrl,
  SD_JWT_VC_INTEGRITY_KEYS,
  TYPE_METADATA_INTEGRITY_KEYS,
} from '../../json-schema/index.js';
import type { SdJwtTypeMetadata, TypeMetadataDependencies } from './types.js';
import { MAX_TYPE_METADATA_CLAIMS, MAX_TYPE_METADATA_DISPLAY } from './types.js';

/** `vct` が Type Metadata の取得先 URL とみなせるか（HTTPS URL のみ）。 */
export function isTypeMetadataUrl(vct: string): boolean {
  return isHttpsUrl(vct);
}

/**
 * SD-JWT VC の `vct#integrity`（draft-ietf-oauth-sd-jwt-vc-22 §2.2.2.3 / §6）が宣言されていないことを
 * 確認する。起点の Type Metadata 文書のハッシュ固定を黙って捨てず、**取得より前に** `3061` で拒否する。
 * 理由・方針・宣言の判定（キーの存在だけ・大文字小文字を区別しない）は W3C VC の `credentialSchema.digestSRI`
 * と共通（`json-schema/integrity.ts` の {@link assertNoUnverifiableIntegrity}）。
 *
 * `claims` は検証済み SD-JWT の復元済みクレーム。
 *
 * @throws `vct#integrity` が宣言されている場合（VericertsError、code `3061`、`integrity_unverifiable`）。
 */
export function assertNoUnverifiableVctIntegrity(claims: Readonly<Record<string, unknown>>): void {
  assertNoUnverifiableIntegrity(claims, SD_JWT_VC_INTEGRITY_KEYS);
}

/**
 * 取得した JSON を Type Metadata として構造検証する。
 *
 * `vct` メンバが取得元 URL と一致することを要求する（別種別のメタデータをすり替えられる
 * 混同攻撃の防止）。`schema` と `schema_uri` の同時指定は draft-ietf-oauth-sd-jwt-vc §6.1 で
 * 禁止されているため拒否する。`claims` / `display` は配列であることを要求する（`extends` チェーンの
 * マージが配列前提のため、非配列を通すと未捕捉の `TypeError` になり FO-3 の fail-open 契約が破れる）。
 * 検証手段の無い `#integrity` も拒否する（{@link assertNoUnverifiableIntegrity}。`extends#integrity` / `schema_uri#integrity`）。
 *
 * @throws 構造不正・`vct` 不一致・`schema` / `schema_uri` 併記・`claims` / `display` の非配列・
 *         検証できない `#integrity` の場合（VericertsError、code `3061`）。
 */
export function assertTypeMetadata(
  document: Record<string, unknown>,
  expectedVct: string,
): SdJwtTypeMetadata {
  if (typeof document.vct !== 'string' || document.vct.length === 0) {
    throw new VericertsError(ErrorCodes.TYPE_METADATA_INVALID, {
      context: { reason: 'vct_missing' },
    });
  }
  if (document.vct !== expectedVct) {
    throw new VericertsError(ErrorCodes.TYPE_METADATA_INVALID, {
      context: { reason: 'vct_mismatch' },
    });
  }
  if (document.schema !== undefined && document.schema_uri !== undefined) {
    throw new VericertsError(ErrorCodes.TYPE_METADATA_INVALID, {
      context: { reason: 'schema_and_schema_uri' },
    });
  }
  if (
    document.schema !== undefined &&
    (typeof document.schema !== 'object' ||
      document.schema === null ||
      Array.isArray(document.schema))
  ) {
    throw new VericertsError(ErrorCodes.TYPE_METADATA_INVALID, {
      context: { reason: 'schema_not_object' },
    });
  }
  for (const key of ['extends', 'schema_uri'] as const) {
    const value = document[key];
    if (value !== undefined && typeof value !== 'string') {
      throw new VericertsError(ErrorCodes.TYPE_METADATA_INVALID, {
        context: { reason: `${key}_not_string` },
      });
    }
  }
  for (const key of ['claims', 'display'] as const) {
    const value = document[key];
    if (value !== undefined && !Array.isArray(value)) {
      throw new VericertsError(ErrorCodes.TYPE_METADATA_INVALID, {
        context: { reason: `${key}_not_array` },
      });
    }
  }
  assertBoundedMetadataArrays(document);
  assertNoUnverifiableIntegrity(document, TYPE_METADATA_INTEGRITY_KEYS);
  return document as unknown as SdJwtTypeMetadata;
}

/**
 * `claims` / `display` の件数と `claims` 要素の形を検査する。
 *
 * 要素数・要素の型が無制限だと、`{}` を敷き詰めた 1 MiB 文書が約 25 倍のヒープになり、`extends` を
 * 10 段たどるだけで RSS が 1 GB を超える。`claims` の各要素は SD-JWT VC §6.3 のとおり `path` 配列を
 * 持つオブジェクトでなければならず、`path` を持たない要素は `mergeClaims` でも残さない。
 */
function assertBoundedMetadataArrays(document: Record<string, unknown>): void {
  const { claims, display } = document;
  if (
    (Array.isArray(claims) && claims.length > MAX_TYPE_METADATA_CLAIMS) ||
    (Array.isArray(display) && display.length > MAX_TYPE_METADATA_DISPLAY)
  ) {
    throw new VericertsError(ErrorCodes.TYPE_METADATA_INVALID, {
      context: { reason: 'metadata_too_large' },
    });
  }
  if (Array.isArray(claims) && !claims.every(hasPathArray)) {
    throw new VericertsError(ErrorCodes.TYPE_METADATA_INVALID, {
      context: { reason: 'claims_entry_invalid' },
    });
  }
}

/** `claims` の要素が `path` 配列を持つオブジェクトか。 */
function hasPathArray(entry: unknown): boolean {
  return (
    typeof entry === 'object' && entry !== null && 'path' in entry && Array.isArray(entry.path)
  );
}

/**
 * Type Metadata / スキーマ文書を 1 件取得する。共有予算（`budget`）があれば本文のバイト数を計上する。
 *
 * 残バイト数が 1 MiB 未満のときは本文上限をその残りに切り詰め、超過は取得失敗（3060。FO-3 で警告通過
 * し得る）ではなく `3061`（`metadata_too_large`）に倒す。予算超過は構造不正と同じく fail-open しない。
 */
async function fetchMetered(
  url: string,
  deps: TypeMetadataDependencies,
  budget: PresentationWorkBudget | undefined,
): Promise<Record<string, unknown>> {
  if (budget === undefined) {
    return await fetchSchemaJson(url, ErrorCodes.TYPE_METADATA_FETCH_FAILED, deps);
  }
  const remaining = remainingWork(budget, 'metadataBytes');
  if (remaining <= 0) {
    throw workBudgetExceeded('metadataBytes');
  }
  try {
    return await fetchSchemaJson(url, ErrorCodes.TYPE_METADATA_FETCH_FAILED, deps, {
      maxBytes: remaining,
      onBytes: (byteLength) => spendWork(budget, 'metadataBytes', byteLength),
    });
  } catch (error) {
    if (
      remaining < MAX_DOCUMENT_BYTES &&
      error instanceof VericertsError &&
      error.context?.reason === 'oversized_body'
    ) {
      throw workBudgetExceeded('metadataBytes');
    }
    throw error;
  }
}

/**
 * `vct` URL から Type Metadata 文書を 1 件取得し構造検証する（`extends` は解決しない）。
 *
 * @param vct Type Metadata の URL（= VC 種別識別子）。
 * @param deps `fetchImpl` の注入。
 * @param budget 取得した本文のバイト数を計上する共有予算（省略時は 1 文書 1 MiB の上限のみ）。
 * @returns 構造検証済みの Type Metadata。
 * @throws 取得失敗（`3060`）・構造不正 / `vct` 不一致 / 総量予算超過（`3061`）。
 */
export async function fetchTypeMetadataDocument(
  vct: string,
  deps: TypeMetadataDependencies = {},
  budget?: PresentationWorkBudget,
): Promise<SdJwtTypeMetadata> {
  return assertTypeMetadata(await fetchMetered(vct, deps, budget), vct);
}

/**
 * `schema_uri` から JSON Schema 文書を取得する。
 *
 * @param schemaUri スキーマ文書の URL（HTTPS のみ）。
 * @param deps `fetchImpl` の注入。
 * @param budget 取得した本文のバイト数を計上する共有予算（省略時は 1 文書 1 MiB の上限のみ）。
 * @returns 取得した JSON Schema。
 * @throws 取得失敗の場合（VericertsError、code `3060`）。総量予算超過は `3061`。
 */
export async function fetchSchemaDocument(
  schemaUri: string,
  deps: TypeMetadataDependencies = {},
  budget?: PresentationWorkBudget,
): Promise<JsonSchema> {
  return await fetchMetered(schemaUri, deps, budget);
}
