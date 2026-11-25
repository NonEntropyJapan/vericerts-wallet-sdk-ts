/**
 * `Wallet.matchCredentialsByPresentationDefinition` が使う VC の選定処理。
 * `matchCredentials` の `presentation_definition` 分岐と評価ロジックを共有する。
 */

import { matchCredentialsByPresentationDefinition as matchCredentialsByPresentationDefinitionImpl } from '../../internal/auth/match-by-presentation-definition.js';
import type { VerifiableCredential } from '../../internal/credential/index.js';
import type { PresentationDefinition } from '../../internal/presentation-exchange/index.js';

/**
 * 保持 VC のうち Presentation Definition に合致するものを返す（`internal/auth/match-by-presentation-definition.ts`
 * の `matchCredentialsByPresentationDefinition` への薄い委譲。純粋関数）。
 *
 * 選定は `auth/matcher.ts` の `selectMatchingCredentials` と同じ方式を用いる。`id` は空・
 * 重複し得るため id 経由の逆引きはせず、各クレデンシャルを単独集合として再評価して寄与有無を
 * 確定する（id なし VC が誤って除外される・同一 id の VC で偽陽性が起きる、という id 逆引き
 * 方式の問題を避けるため）。
 *
 * @param pd 評価対象の Presentation Definition（`parsePresentationDefinition` でパース済み）。
 * @param credentials 評価対象の保持 VC（呼び出し側が処理制限を除外済みであること）。
 * @returns マッチした VC（`credentials` の順序、重複なし）。
 */
export function matchCredentialsByPresentationDefinitionWith(
  pd: PresentationDefinition,
  credentials: readonly VerifiableCredential[],
): VerifiableCredential[] {
  return matchCredentialsByPresentationDefinitionImpl(pd, credentials);
}
