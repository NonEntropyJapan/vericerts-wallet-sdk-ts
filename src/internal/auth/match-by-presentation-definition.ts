/**
 * Presentation Definition（DIF PEx v2）を保持 VC 集合に対して評価し、マッチする VC を返す純粋関数。
 *
 * `matchCredentials` の `presentation_definition` 分岐と、Wallet の `matchCredentialsByPresentationDefinition` が共有する。
 *
 * `credentials` を `toQueryableFromVc`（DCQL/PEx v2 共通の正規化。format は既定の `jwt_vc_json`）で評価用に
 * 正規化し、`evaluatePresentationDefinition`（`presentation-exchange` モジュール、PEx v2 評価エンジン
 * 本体）へ委譲する。複数の Input Descriptor にマッチした VC も重複排除して 1 回だけ返す。
 */

import type { VerifiableCredential } from '../credential/index.js';
import {
  createPexBudget,
  evaluatePresentationDefinitionWithBudget,
  type PexBudget,
  type PresentationDefinition,
  parsePresentationDefinition,
} from '../presentation-exchange/index.js';
import { toQueryableFromVc } from './matcher.js';

/**
 * 保持 VC のうち Presentation Definition に合致するものを返す。
 *
 * @param pd 評価対象の Presentation Definition（`parsePresentationDefinition` でパース済み）。
 * @param credentials 評価対象の保持 VC（呼び出し側が処理制限を除外済みであること）。
 * @param budget 評価量予算（SDK 内部用。既定は呼び出しごとに新しく作る。テストが小さい予算を注入して打ち切りを決定的に踏む）。
 * @returns マッチした VC（`credentials` の順序、重複なし）。
 */
export function matchCredentialsByPresentationDefinition(
  pd: PresentationDefinition,
  credentials: readonly VerifiableCredential[],
  budget: PexBudget = createPexBudget(),
): VerifiableCredential[] {
  // 選定は各クレデンシャルを単独集合として再評価し、寄与有無で判定する
  // （`auth/matcher.ts` の `selectMatchingCredentials` と同方針。id は空・重複し得るため
  // id 経由の逆引きはしない）。
  // format ラベルは既定（`jwt_vc_json`）のまま。ウォレット保管層が VC ごとの format ヒントを持たない
  // 現状、この層に `jwt_vc_json-ld` を選ぶ根拠が無い（保管層が持つようになれば別 Issue で通す）。
  // 予算（JSONPath 走査量・正規表現ステップ）は Presentation Request 1 件で共有する。VC ごとに
  // 新しい予算を作ると、Verifier 由来の `path` / `pattern` の評価量が VC 件数倍になる。
  return credentials.filter(
    (vc) =>
      evaluatePresentationDefinitionWithBudget(pd, [toQueryableFromVc(vc)], budget).length > 0,
  );
}

/**
 * raw JSON の Presentation Definition を構造検証してから評価する（`matchCredentials` の
 * `presentation_definition` 分岐の入口）。
 *
 * 構造検証（`parsePresentationDefinition`）と評価（`evaluatePresentationDefinition`）を 1 つの
 * 関数にまとめてあるのは、呼び出し元（`match-credentials/index.ts`）が本モジュールを**動的
 * import** で読み込むためである。`parsePresentationDefinition` だけを静的 import すると、
 * `presentation-exchange` バレル（= PEx v2 評価エンジン = `jsonpath-plus`）が再び呼び出し元の
 * 静的依存グラフへ戻り、分離の意味が無くなる。
 *
 * @param raw 未検証の Presentation Definition（Verifier 由来の raw JSON）。
 * @param credentials 評価対象の保持 VC（呼び出し側が処理制限を除外済みであること）。
 * @throws `presentation_definition` の構造不正（`OID4VP_REQUEST_PARSE_FAILED`、code `8030`）。
 */
export function matchCredentialsByPresentationDefinitionJson(
  raw: Readonly<Record<string, unknown>>,
  credentials: readonly VerifiableCredential[],
): VerifiableCredential[] {
  const pd: PresentationDefinition = parsePresentationDefinition(raw);
  return matchCredentialsByPresentationDefinition(pd, credentials);
}
