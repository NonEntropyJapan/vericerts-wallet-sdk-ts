/**
 * OpenID Federation の Subordinate Statement 取得・検証プリミティブ。
 *
 * OpenID Federation 1.0 §8（Fetch）と §4（Trust Chain）に基づく。
 *
 * Trust Chain 構築（`trust-chain.ts`）から切り出した「上位（parent）が発行する child についての
 * Subordinate Statement を fetch endpoint から取得し、上位の鍵で署名検証したうえで child の鍵集合が
 * 一致することを確認する」責務をまとめる。JWK Set の等価判定（`jwksEqual`）もここに置く。
 *
 * キャッシュ層（`statement-cache.ts`）は任意で注入する。キャッシュキーは
 * **`sub` クエリパラメータを含む fetch endpoint URL 全体**である。1 つの fetch endpoint が多数の
 * subject についての Statement を配信するため、endpoint だけをキーにすると別の subject の Statement を
 * 返してしまう。これは性能上の都合ではなく正当性の要件である。
 *
 * エラーコード: `entity-configuration.ts` と同じ境界で分ける。
 * - 取得（transport）失敗（ネットワーク / タイムアウト / HTTP 4xx・5xx / 非 HTTPS リダイレクト /
 *   Content-Type 不一致 / 空レスポンス）→ `FEDERATION_FETCH_FAILED`（5011、再試行可）。negative cache の対象。
 * - 署名 / `iss`・`sub` / 有効期間 / `jwks` 一致の検証失敗、および fetch endpoint 自体の不備
 *   → `TRUST_CHAIN_INVALID`（5010）。negative cache の対象外。
 *
 * 取得失敗（5011）は 30 秒の negative cache の対象とする。検証失敗（5010）はキャッシュしない。
 * 例外メッセージや context に entity_id・URL・JWT・鍵を含めない。
 */

import { ErrorCodes, VericertsError } from '../../errors.js';
import { isPublicHttpsUrl } from '../../http/public-https-url.js';
import type { Metrics } from '../../observability/metrics.js';
import { nonObjectPrototypeProperty, ownProperty } from '../../prototype-safety/own-property.js';
import { resolveCachedStatement } from './cache/statement-cache.js';
import { instrumentFederationStatementFetch } from './cache/statement-observability.js';
import type { ResolveEntityConfigurationDeps } from './entity-configuration.js';
import type {
  EntityConfiguration,
  EntityMetadata,
  FederationEntityMetadata,
  JsonWebKeySet,
} from './federation-types.js';
import { fetchStatementJwt } from './statement/fetch-statement.js';
import {
  assertStatementTimeValid,
  decodeAndVerifyStatementWithKey,
  type VerifiedStatement,
} from './statement/statement.js';
import { consumeStatementBudget, type StatementBudget } from './statement/statement-budget.js';

/**
 * JWK Set を正規化した JSON 文字列に変換して比較可能にする。
 *
 * 鍵の集合が等価かを判定するために、各鍵のクレームをキー昇順で直列化する。順序非依存にするため
 * 鍵ごとの直列化結果をソートして結合する。
 */
function canonicalizeJwks(jwks: JsonWebKeySet): string {
  const serializedKeys = jwks.keys
    .map((key) => JSON.stringify(sortObjectKeys(key as Record<string, unknown>)))
    .sort();
  return JSON.stringify(serializedKeys);
}

/** オブジェクトのキーを昇順に並べ替えた新しいオブジェクトを返す（浅い正規化）。 */
function sortObjectKeys(obj: Record<string, unknown>): Record<string, unknown> {
  const sorted: Record<string, unknown> = {};
  for (const key of Object.keys(obj).sort()) {
    sorted[key] = obj[key];
  }
  return sorted;
}

/**
 * 2 つの JWK Set が同一の鍵集合を表すか判定する。
 *
 * @param a JWK Set。
 * @param b JWK Set。
 * @returns 正規化後に一致すれば `true`。
 */
export function jwksEqual(a: JsonWebKeySet, b: JsonWebKeySet): boolean {
  return canonicalizeJwks(a) === canonicalizeJwks(b);
}

/** 上位の `federation_fetch_endpoint` を取り出す。未設定なら不成立。 */
function requireFetchEndpoint(config: EntityConfiguration): string {
  // 省略されたメンバが `Object.prototype` の汚染値で埋まらないよう own に限って読む。
  const metadata = ownProperty<EntityMetadata>(config.statement, 'metadata');
  const federationEntity =
    metadata === undefined
      ? undefined
      : ownProperty<FederationEntityMetadata>(metadata, 'federation_entity');
  const endpoint =
    federationEntity === undefined
      ? undefined
      : ownProperty<unknown>(federationEntity, 'federation_fetch_endpoint');
  if (typeof endpoint !== 'string' || endpoint.length === 0) {
    throw new VericertsError(ErrorCodes.TRUST_CHAIN_INVALID);
  }
  return endpoint;
}

/**
 * Subordinate Statement の取得 URL を組み立てる（`sub` を含む）。
 *
 * OpenID Federation 1.0 §8: `GET <fetch_endpoint>?sub=<child>`。上位（issuer）方向の指定は
 * endpoint URL 自体に含まれる想定で、`sub` に child を付与する。
 *
 * この URL はそのままキャッシュキーになる。`sub` を含めるのは必須で、含めないと同一 endpoint 配下の
 * 別 subject の Statement をキャッシュから返してしまう。
 *
 * @param fetchEndpoint 上位の federation_fetch_endpoint。
 * @param subject child の Entity Identifier。
 * @returns `sub` を付与した取得 URL。
 * @throws URL でない / 公開 HTTPS でない場合（VericertsError、TRUST_CHAIN_INVALID）。
 */
function subordinateStatementUrl(fetchEndpoint: string, subject: string): string {
  let url: URL;
  try {
    url = new URL(fetchEndpoint);
  } catch {
    throw new VericertsError(ErrorCodes.TRUST_CHAIN_INVALID);
  }
  // `federation_fetch_endpoint` は上位 Statement 由来の外部 URL。公開 HTTPS 宛だけを許す。
  if (!isPublicHttpsUrl(url.toString())) {
    throw new VericertsError(ErrorCodes.TRUST_CHAIN_INVALID);
  }
  url.searchParams.set('sub', subject);
  return url.toString();
}

/**
 * child の正当な鍵集合が Subordinate Statement で保証されるか検証する。
 *
 * 上位（parent）の Entity Configuration の鍵で Subordinate Statement を検証し、その `iss` /
 * `sub` / 有効期間・`jwks`（= parent が保証する child の鍵）を確認する。Subordinate Statement 内の
 * `jwks` が child 自身が主張した鍵集合と一致することを要求する。
 *
 * `deps.statementCache` 注入時は `sub` を含む取得 URL をキーに生 JWT をキャッシュする。命中時も
 * ネットワークに出ないだけで、上記の検証は毎回やり直す。
 *
 * @param parent 上位の検証済み Entity Configuration。
 * @param child child の Entity Identifier。
 * @param childJwks child が自己 Entity Configuration で主張した鍵集合。
 * @param nowSeconds 現在時刻（エポック秒）。
 * @param deps 依存注入（`fetchFn` / キャッシュ）。
 * @param budget Trust Chain 構築 1 回ぶんの Statement 本文量の予算（省略時は計上しない）。
 * @returns 検証済み Subordinate Statement と、その署名を検証した鍵の `kid`。
 * @throws 取得失敗の場合（VericertsError、FEDERATION_FETCH_FAILED）、
 *         検証失敗の場合（VericertsError、TRUST_CHAIN_INVALID）、
 *         TTL 上限設定が不正な場合（VC_SCHEMA_INVALID、3002）。
 */
export async function verifySubordinate(
  parent: EntityConfiguration,
  child: string,
  childJwks: JsonWebKeySet,
  nowSeconds: number,
  deps: ResolveEntityConfigurationDeps,
  budget?: StatementBudget,
): Promise<VerifiedStatement> {
  const endpoint = requireFetchEndpoint(parent);
  // `sub` を含む URL 全体をキャッシュキーにする（別 subject と共有させない）。
  const url = subordinateStatementUrl(endpoint, child);
  // 継承した `fetchFn` は Subordinate Statement の取得先を攻撃者の関数へ委譲する。
  // 関数値の DI は own 限定では読めない（証明書ピンニング付き fetch を prototype メソッドで
  // 注入した正当な実装が無言でグローバル fetch へ差し替わる）。`Object.prototype` 由来だけを弾く。
  const fetchFn = nonObjectPrototypeProperty<typeof fetch>(deps, 'fetchFn');
  const metrics = nonObjectPrototypeProperty<Metrics>(deps, 'metrics');

  return resolveCachedStatement<VerifiedStatement>(
    instrumentFederationStatementFetch(metrics, {
      key: url,
      kind: 'subordinate-statement',
      deps,
      nowSeconds,
      fetchJwt: () => fetchStatementJwt(url, fetchFn),
      verify: (jwt) => {
        // Subordinate Statement は「上位（parent）の鍵」で署名される。どの鍵で成立したかは
        // 鍵無効化宣言との突合（trust-chain.ts）に必要なため取りこぼさない。
        consumeStatementBudget(budget, jwt);
        const verified = decodeAndVerifyStatementWithKey(jwt, parent.statement.jwks);
        const statement = verified.statement;
        if (statement.iss !== parent.entityId || statement.sub !== child) {
          throw new VericertsError(ErrorCodes.TRUST_CHAIN_INVALID);
        }
        assertStatementTimeValid(statement, nowSeconds);
        // parent が保証する child の鍵（Subordinate Statement の jwks）が、child 自身の主張と一致すること。
        if (!jwksEqual(statement.jwks, childJwks)) {
          throw new VericertsError(ErrorCodes.TRUST_CHAIN_INVALID);
        }
        // 生 JWT も返す（`FederationEntityCache.trustChain` の組み立てに必要）。
        return { value: { ...verified, jwt }, statement };
      },
    }),
  );
}
