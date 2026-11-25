/**
 * Credential Chain 走査量の上限。
 *
 * `maxDepth`（深さ）だけでは、各 VC が親 ID を数件並べるだけで走査が指数的に展開される
 * （親 4 件・深さ 10 で `resolveCredential` 約 140 万回・RSS 2.6 GB）。`resolveCredential` は VC が指す
 * 任意 ID の解決（ネットワーク往復）を行う DI なので、攻撃者の VC 1 件が無制限の外向き fetch とメモリ枯渇を
 * 起こせた。正規のチェーンは数ノード・親 1〜数件なので、いずれも十分な余裕を持たせた固定上限にしている。
 */

/** 1 回の走査で解決（`resolveCredential`）・評価する相異なる VC の最大数。 */
export const MAX_CHAIN_NODES = 128;

/** 1 つの VC が宣言できる親エッジ（4 関係の合計、`(関係, 親 ID)` で重複排除後）の最大数。 */
export const MAX_CHAIN_PARENT_EDGES = 16;

/**
 * 1 回の走査でキューに積む訪問（経路）の最大数。同じ VC への再到達・再展開（DAG）も 1 訪問として数えるので、
 * ノード数が少なくても合流を重ねた指数展開と、キュー・訪問記録のメモリ膨張を止める。
 */
export const MAX_CHAIN_VISITS = 1024;

// 走査量の上限超過は `chainTooLarge()`（`primitives/presentation-work-budget.ts`、`CHAIN_TOO_DEEP` 4051・
// `reason: "chain_too_large"`）で拒否する。VP 全体の合計は `PresentationWorkBudget` の `chainNodes` /
// `chainVisits`（`PRESENTATION_WORK_LIMITS`）と `MAX_PRESENTATION_CREDENTIALS` が持つ。
