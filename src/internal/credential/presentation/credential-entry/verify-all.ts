/**
 * VP の内包 VC 全件の検証ループ（`credential-results.ts` の `verifyEmbeddedCredentials` の実体）。
 *
 * 個々の VC を検証する前に、VP 1 通ぶんの共有状態を作って各要素へ配る:
 * - 要素数の上限（`MAX_PRESENTATION_CREDENTIALS`）を署名検証より前に適用する。
 * - 仕事量の共有予算（`PresentationWorkBudget`）と Trusted Issuer List の発行者 DID 索引（`verify-scope.ts`）。
 *   署名検証・信頼リスト走査・（同じ予算を渡した）chain / type metadata がすべて同じ予算を消費する。
 * - 完全一致する文字列の要素は 1 度だけ検証し、結果を共有する（重複で署名検証を何度も走らせない）。
 */

import { assertCredentialCount } from '../../../primitives/presentation-work-budget.js';
import { verifyEmbeddedCredentialEntry } from '../credential-entry-verify.js';
import type {
  EmbeddedCredentialEntry,
  EmbeddedCredentialVerifyInput,
  VerificationResult,
} from '../credential-results.js';
import { runInVerifyScope } from './verify-scope.js';

/**
 * 内包 VC 全件を検証する。要素の並び順は入力と 1 対 1 に対応する（スキップしない）。
 *
 * @throws 要素数が上限超過、または共有予算を使い切った場合（`VC_SCHEMA_INVALID` 3002、
 *         `reason: "work_budget_exceeded"`）。VP 全体を拒否する fail-closed。
 */
export function verifyAllEmbeddedEntries(
  entries: ReadonlyArray<EmbeddedCredentialEntry>,
  input: EmbeddedCredentialVerifyInput,
): VerificationResult[] {
  assertCredentialCount(entries.length);
  return runInVerifyScope(input, () => {
    const byString = new Map<string, VerificationResult>();
    return entries.map((entry, index) => {
      if (typeof entry !== 'string') {
        return verifyEmbeddedCredentialEntry(entry, index, input);
      }
      let result = byString.get(entry);
      if (result === undefined) {
        result = verifyEmbeddedCredentialEntry(entry, index, input);
        byString.set(entry, result);
      }
      return result;
    });
  });
}
