/**
 * 保持 VC による被覆判定。
 *
 * `select.ts` から切り出し、`select.ts` が再エクスポートする（`Linterly` の行数上限対応での
 * ファイル分割。責務・公開 API に変更はない）。
 */

import type { WorkBudget } from '../../primitives/work-budget.js';
import { SD_JWT_VC_TYP, SD_JWT_VC_TYP_LEGACY } from '../sdjwt/typ.js';
import { satisfiesRequirement } from './constraints.js';
import type { FormatCoverage, NegotiableCredential, VpFormatRequirement } from './types.js';
import { chargeFormatWork, createFormatWorkBudget } from './work.js';

/**
 * 被覆判定でのみ用いる SD-JWT VC の別名グループ。
 *
 * `dc+sd-jwt`（既定）と `vc+sd-jwt`（旧識別子）は同一クレデンシャル型の別名である。Verifier が
 * `vp_formats` に両方を併記するのは「どちらの識別子で発行されたものでも受理する」という意思表示で
 * あって「両方を提示せよ」ではない。
 *
 * 適用範囲の限定（重要）:
 * - 別名グループ化は `canFulfillFormats` の被覆判定だけに効く。`selectBestVC` の候補絞り込み
 *   （`satisfiesRequirement`）と DCQL 評価（`auth/dcql/dcql.ts`）の format 照合は**完全一致のまま**である。
 *   `typ` は JWS ヘッダ＝署名対象なので、保持している `vc+sd-jwt` を `dc+sd-jwt` として提示すること
 *   は原理的にできない。
 * - 効くのは新旧が**併記されている**ときだけ。要求が `dc+sd-jwt` のみで保持が `vc+sd-jwt` のみなら
 *   従来どおり未被覆（`fullyCovered=false`）になる。
 * - 他フォーマット（`jwt_vc_json` / `ldp_vc` / `mso_mdoc` 等）の被覆判定には影響しない。
 */
const SD_JWT_VC_COVERAGE_ALIASES: ReadonlySet<string> = new Set([
  SD_JWT_VC_TYP,
  SD_JWT_VC_TYP_LEGACY,
]);

/**
 * 保持 VC で Verifier の各要求フォーマットを満たせるかを判定する。
 *
 * 要求フォーマット毎に、フォーマット一致かつ `alg` 制約を満たす保持 VC が 1 件以上あるかを調べる。
 * ただし SD-JWT VC の新旧識別子が併記された場合のみ、両者を同一クレデンシャル型の別名グループ
 * として扱い、いずれか一方を被覆していれば当該 SD-JWT VC 要求を満たしたものとする
 * （`SD_JWT_VC_COVERAGE_ALIASES` の注記を参照。`matchedFormats` には実際に一致した識別子だけが
 * 入り、他方は `unmatchedFormats` に残さない）。
 *
 * @param required Verifier の `vp_formats` 要求。
 * @param holding 保持する正規化候補 VC。
 * @param budget 仕事量予算。省略時は呼び出しごとに新しい予算。超過は 3050（`format_work_budget_exceeded`）。
 * @returns 被覆状況（`fullyCovered` / `matchedFormats` / `unmatchedFormats`）。
 */
export function canFulfillFormats(
  required: VpFormatRequirement,
  holding: readonly NegotiableCredential[],
  budget: WorkBudget = createFormatWorkBudget(),
): FormatCoverage {
  const matchedFormats: string[] = [];
  const exactUnmatched: string[] = [];
  for (const [format, constraint] of Object.entries(required)) {
    // フォーマット 1 件 × 保持 VC 全件の走査（`vc.format === format` の比較）を、先頭の一致で止まる場合も含め
    // 入口で計上する（フォーマット数 K × 保持数 C の積を予算で縛る）。
    chargeFormatWork(budget, holding.length + 1);
    const single = { [format]: constraint };
    const covered = holding.some(
      (vc) => vc.format === format && satisfiesRequirement(vc, single, budget),
    );
    if (covered) {
      matchedFormats.push(format);
    } else {
      exactUnmatched.push(format);
    }
  }
  // 併記された SD-JWT VC 識別子のいずれかを被覆できていれば、他方の識別子は未被覆として残さない。
  const sdJwtVcCovered = matchedFormats.some((format) => SD_JWT_VC_COVERAGE_ALIASES.has(format));
  const unmatchedFormats = sdJwtVcCovered
    ? exactUnmatched.filter((format) => !SD_JWT_VC_COVERAGE_ALIASES.has(format))
    : exactUnmatched;
  return {
    fullyCovered: unmatchedFormats.length === 0,
    matchedFormats,
    unmatchedFormats,
  };
}
