/**
 * OpenID Federation Entity Configuration 取得（`resolveEntityConfiguration`）。
 *
 * OpenID Federation 1.0 §3.1 / §9 に基づく。
 *
 * Entity Configuration はエンティティ自身が自己の JWKS で自己署名した Entity Statement で、
 * `<entity_id>/.well-known/openid-federation` で公開される（`iss == sub`）。本モジュールは:
 *
 * 1. `entity_id` を well-known URL に変換して HTTPS GET（タイムアウト / AbortController）。
 * 2. compact JWS をデコードし、payload 内の自己 `jwks` で自己署名を検証。
 * 3. `iss == sub == entity_id` と有効期間（`iat` / `exp`）を検証。
 *
 * `fetch` は既定でランタイムのグローバルを使うが、テスト容易性のため DI seam
 * （`ResolveEntityConfigurationDeps.fetchFn` / `now`）を持たせる。
 *
 * キャッシュ層（`statement-cache.ts`）は任意で注入する。注入時も 2-3 の検証は
 * キャッシュ命中・ミスに関わらず毎回実行する（キャッシュするのは生 JWT だけであり、検証済み
 * オブジェクトではない）。TTL は Statement 自身の `exp` に従い、鍵無効化宣言の伝播 SLA（600 秒）で
 * 頭打ちにする。
 *
 * エラーコード:
 * - 取得失敗（ネットワーク / タイムアウト / HTTP 4xx・5xx / 非 HTTPS）→ `FEDERATION_FETCH_FAILED`（5011、再試行可）。
 * - JWT 形式不正 / 署名不成立 / iss≠sub / 期限切れ → `TRUST_CHAIN_INVALID`（5010）。
 *
 * セキュリティ上の注意:
 * - 例外メッセージや `context` に entity_id・URL・JWT・鍵を含めない。
 */

import { ErrorCodes, VericertsError } from '../../errors.js';
import { isPublicHttpsUrl } from '../../http/public-https-url.js';
import type { Metrics } from '../../observability/metrics.js';
import { nonObjectPrototypeProperty, ownProperty } from '../../prototype-safety/own-property.js';
import { type FederationCacheDeps, resolveCachedStatement } from './cache/statement-cache.js';
import { instrumentFederationStatementFetch } from './cache/statement-observability.js';
import {
  createEntityConfigurationFailOpen,
  type EntityConfigurationFailOpenDeps,
} from './fail-open/entity-configuration-fail-open.js';
import type { EntityConfiguration } from './federation-types.js';
import { fetchStatementJwt } from './statement/fetch-statement.js';
import {
  assertStatementTimeValid,
  decodeStatementJws,
  selfJwksOf,
  verifyDecodedStatement,
} from './statement/statement.js';
import { consumeStatementBudget, type StatementBudget } from './statement/statement-budget.js';

/** OpenID Federation Entity Configuration の well-known パス（RFC 8414 系）。 */
const WELL_KNOWN_PATH = '/.well-known/openid-federation';

/**
 * `resolveEntityConfiguration` の依存注入（テスト用の seam + 任意のキャッシュ層）。
 *
 * キャッシュ関連（`FederationCacheDeps`）はすべて任意であり、未指定なら従来どおり毎回取得する。
 * `subordinate.ts` / `trust-chain.ts` も同じ seam を共有するため、一度注入すれば Trust Chain
 * 構築中の Entity Configuration と Subordinate Statement の両方に同じキャッシュが効く。
 *
 * FO-6 関連（`EntityConfigurationFailOpenDeps`）も任意で、`failOpenWindow` を渡さない限り取得失敗は
 * 従来どおり fail-closed である。seam を共有していても FO-6 が効くのは Entity Configuration の取得
 * だけで、`subordinate.ts` の取得失敗は常に fail-closed のまま。
 */
export interface ResolveEntityConfigurationDeps
  extends FederationCacheDeps,
    EntityConfigurationFailOpenDeps {
  /** HTTP 取得関数。既定はランタイムのグローバル `fetch`。 */
  readonly fetchFn?: typeof fetch;
  /** 現在時刻（エポック秒）を返す関数。既定は `Date.now()` 由来。 */
  readonly now?: () => number;
}

/**
 * Entity Identifier を Entity Configuration の well-known URL に変換する。
 *
 * OpenID Federation 1.0 §9: `entity_id` のパス末尾に `/.well-known/openid-federation` を付加する
 * （パスを含む場合も末尾付加。ここでは末尾スラッシュを正規化して結合する）。公開 HTTPS を要求する。
 *
 * @param entityId Entity Identifier（HTTPS URL）。
 * @returns well-known URL 文字列。
 * @throws 公開 HTTPS URL でない場合（VericertsError、TRUST_CHAIN_INVALID）。
 */
export function entityConfigurationUrl(entityId: string): string {
  let url: URL;
  try {
    url = new URL(entityId);
  } catch {
    throw new VericertsError(ErrorCodes.TRUST_CHAIN_INVALID);
  }
  // `entity_id` は `authority_hints` 等の外部由来で攻撃者が選べる。取得前に公開 HTTPS 宛であることを
  // 確かめ、内部ホスト・クラウドメタデータ宛の blind SSRF を作らない。
  if (!isPublicHttpsUrl(url.toString())) {
    throw new VericertsError(ErrorCodes.TRUST_CHAIN_INVALID);
  }
  // query / fragment は entity_id に含めない前提。末尾スラッシュを畳んでパスに付加する。
  const basePath = url.pathname.endsWith('/') ? url.pathname.slice(0, -1) : url.pathname;
  return `${url.origin}${basePath}${WELL_KNOWN_PATH}`;
}

/**
 * Entity Configuration を HTTPS 経由で取得し、自己署名と有効性を検証する。
 *
 * `deps.statementCache` を注入した場合は well-known URL をキーに生 JWT をキャッシュする。命中時も
 * ネットワークに出ないだけで、デコード・自己署名検証・`iss`/`sub` 一致・有効期間検証は毎回行う。
 *
 * さらに `deps.failOpenWindow` を注入した場合に限り、取得失敗時に TTL 切れのキャッシュを再検証して
 * 通過させる経路（FO-6）が有効になる。通過時は `warnings` を添えて返す。
 *
 * **Trust Anchor 自身の Entity Configuration を解決する呼び出しでは `deps.failOpenWindow` を
 * 渡さないこと**（FO-6 を使わない）。アンカーの鍵には Subordinate Statement の `revoked_keys`
 * （FC-11）に相当する無効化経路が存在しないため、stale なアンカー EC を FO-6 で受理すると
 * 漏洩鍵での署名検証をそのまま許してしまう。`buildTrustChain` は
 * `fail-open/trust-chain-anchor-deps.ts` の `anchorEntityConfigurationDeps` でこれを機械的に
 * 保証しているが、本関数を直接呼ぶ他の呼び出し側は各自で守る必要がある。
 *
 * @param entityId Entity Identifier（HTTPS URL）。
 * @param deps 依存注入（`fetchFn` / `now` / キャッシュ）。省略時はランタイム既定・キャッシュ無し。
 * @param budget Trust Chain 構築 1 回ぶんの Statement 本文量の予算（`buildTrustChain` が渡す）。
 * @returns 取得・検証済み Entity Configuration。
 * @throws 取得失敗（FEDERATION_FETCH_FAILED、5011）・検証失敗（TRUST_CHAIN_INVALID、5010）の場合、
 *         TTL 上限設定が不正な場合（VC_SCHEMA_INVALID、3002）。
 */
export async function resolveEntityConfiguration(
  entityId: string,
  deps: ResolveEntityConfigurationDeps = {},
  budget?: StatementBudget,
): Promise<EntityConfiguration> {
  // 任意の依存注入は自身のプロパティに限って読む。継承した `now` は Entity
  // Statement の有効期間（exp / iat）と鍵無効化（revoked_at）の突合を攻撃者が選んだ時刻で
  // 行わせ、期限切れ Statement・失効済み鍵で組んだチェーンを成立させる。継承した `fetchFn` は
  // Statement の取得先を攻撃者の関数へ委譲する。
  // 関数値の DI は own 限定では読めない（証明書ピンニング付き fetch を prototype メソッドで
  // 注入した正当な実装が無言でグローバル fetch へ差し替わる）。`Object.prototype` 由来だけを弾く。
  const fetchFn = nonObjectPrototypeProperty<typeof fetch>(deps, 'fetchFn');
  const nowFn = ownProperty<() => number>(deps, 'now');
  const nowSeconds = Math.floor((nowFn?.() ?? Date.now()) / 1000);
  const url = entityConfigurationUrl(entityId);
  const metrics = nonObjectPrototypeProperty<Metrics>(deps, 'metrics');
  const failOpen = createEntityConfigurationFailOpen(deps, url);

  const config = await resolveCachedStatement<EntityConfiguration>(
    instrumentFederationStatementFetch(metrics, {
      key: url,
      kind: 'entity-configuration',
      deps,
      nowSeconds,
      fetchJwt: failOpen.trackFetch(() => fetchStatementJwt(url, fetchFn)),
      verify: (jwt) => {
        const value = verifyEntityConfiguration(entityId, jwt, nowSeconds, budget);
        return { value, statement: value.statement };
      },
      ...failOpen.hook,
    }),
  );
  const warning = failOpen.warning();
  return warning === undefined ? config : { ...config, warnings: [warning] };
}

/**
 * 取得済みの Entity Configuration JWT を検証する（自己署名 / iss==sub / 有効期間）。
 *
 * fetch 経路とは独立に検証したい場合（キャッシュ済み JWT の再検証等）にも使える。
 *
 * @param entityId 期待する Entity Identifier。
 * @param jwt compact JWS 文字列。
 * @param nowSeconds 現在時刻（エポック秒）。
 * @param budget Trust Chain 構築 1 回ぶんの Statement 本文量の予算（省略時は計上しない）。
 * @returns 検証済み Entity Configuration。
 * @throws 検証失敗の場合（VericertsError、TRUST_CHAIN_INVALID）。
 */
export function verifyEntityConfiguration(
  entityId: string,
  jwt: string,
  nowSeconds: number,
  budget?: StatementBudget,
): EntityConfiguration {
  // デコード・JSON パースへ進む前に、連鎖全体の本文量を数える。
  consumeStatementBudget(budget, jwt);
  // Entity Configuration は自己署名。payload 内の自己 `jwks` を鍵源として署名検証する。
  // この jwks で署名が成立して初めて payload 全体の完全性が保証される（自己署名モデル）。
  // JWT のデコード（JSON パース）は 1 回だけで、鍵源の取り出しと署名検証が同じ結果を使う。
  const decoded = decodeStatementJws(jwt);
  const { statement } = verifyDecodedStatement(decoded, selfJwksOf(decoded));

  if (statement.iss !== statement.sub) {
    throw new VericertsError(ErrorCodes.TRUST_CHAIN_INVALID);
  }
  if (statement.sub !== entityId) {
    throw new VericertsError(ErrorCodes.TRUST_CHAIN_INVALID);
  }
  assertStatementTimeValid(statement, nowSeconds);

  return { entityId, statement, jwt };
}
