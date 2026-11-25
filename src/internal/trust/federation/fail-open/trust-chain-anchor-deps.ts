/**
 * Trust Anchor 自身の Entity Configuration 解決に使う deps の組み立て（FO-6 対象外化）。
 *
 *
 * `trust-chain.ts` から分離したのは `trust-chain-revocation.ts` と同じ理由（1 ファイル 300 行以下、
 * `federation/` 直下の合計行数上限）。`fail-open/` 配下に置くのは、本モジュールが FO-6 を
 * **無効化する**ための deps 組み立てであり、他の FO-6 実装（`entity-configuration-fail-open.ts`）と
 * 主題を共有するため。
 *
 * FO-6（Entity Configuration 到達不能時の stale キャッシュ利用）は中間 / Leaf ノードには適用してよいが、
 * Trust Anchor 自身には適用しない。Trust Anchor の鍵には Subordinate Statement の `revoked_keys` に
 * 相当する無効化経路（FC-11）が存在しない（無効化を宣言する「上位」が Trust Anchor には無い）ため、
 * stale なアンカー EC（ローテーション済みの旧鍵を含みうる）を FO-6 で受理すると、漏洩鍵での署名検証を
 * そのまま許してしまう。アンカーの EC 解決だけは常に fail-closed に倒す。
 */

import type { Metrics } from '../../../observability/metrics.js';
import { nonObjectPrototypeProperty, ownProperty } from '../../../prototype-safety/own-property.js';
import type { ResolveEntityConfigurationDeps } from '../entity-configuration.js';

/** `buildTrustChain` の依存注入（`resolveEntityConfiguration` と同じ seam を共有）。 */
export type BuildTrustChainDeps = ResolveEntityConfigurationDeps;

/**
 * Trust Anchor 自身の Entity Configuration 解決に使う deps を組み立てる（`failOpenWindow` を落とす）。
 *
 * `failOpenWindow` だけを落とし、他のフィールドは呼び出し側と同じ読み取り規律（own 限定 /
 * `Object.prototype` 鎖読み）で 1 つずつ転記する。`{ ...deps }` で丸ごと複製
 * しないのは、スプレッドが拾うのは own 列挙可能プロパティだけであり、クラスインスタンスとして
 * 注入された `fetchFn` / `metrics`（プロトタイプメソッド・アクセサ経由、`own-property.ts` が
 * 想定する正当な DI パターン）を無言で落としてしまうため。
 *
 * @param deps 呼び出し側が渡した Trust Chain 構築用の依存注入。
 * @returns `failOpenWindow` / FO-6 関連フィールドを含まない deps（アンカーの EC 解決専用）。
 */
export function anchorEntityConfigurationDeps(deps: BuildTrustChainDeps): BuildTrustChainDeps {
  const fetchFn = nonObjectPrototypeProperty<typeof fetch>(deps, 'fetchFn');
  const now = ownProperty<() => number>(deps, 'now');
  const metrics = nonObjectPrototypeProperty<Metrics>(deps, 'metrics');
  const statementCache = nonObjectPrototypeProperty<BuildTrustChainDeps['statementCache']>(
    deps,
    'statementCache',
  );
  const maxTtlSeconds = ownProperty<number>(deps, 'maxTtlSeconds');
  const onCacheEvent = nonObjectPrototypeProperty<BuildTrustChainDeps['onCacheEvent']>(
    deps,
    'onCacheEvent',
  );
  return {
    ...(fetchFn === undefined ? {} : { fetchFn }),
    ...(now === undefined ? {} : { now }),
    ...(metrics === undefined ? {} : { metrics }),
    ...(statementCache === undefined ? {} : { statementCache }),
    ...(maxTtlSeconds === undefined ? {} : { maxTtlSeconds }),
    ...(onCacheEvent === undefined ? {} : { onCacheEvent }),
    // failOpenWindow / failSafePolicy / requestConsent / onPolicyEvent / auditContext は
    // 意図的に含めない。`failOpenWindow` 未指定なら FO-6 は不活性になる
    // （`createEntityConfigurationFailOpen` の既定）ため、残る FO-6 関連フィールドも転記不要。
  };
}
