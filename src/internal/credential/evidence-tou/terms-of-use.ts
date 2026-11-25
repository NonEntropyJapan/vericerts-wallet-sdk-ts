/**
 * W3C VC の `termsOfUse` を構造検証し、Holder が使う VC や Verifier が受け取った VP の利用条件を評価する。
 *
 * 評価モデル: `termsOfUse[]` の各エントリの permission / prohibition / obligation を
 * ODRL 風に順次評価する。制約（constraint）で用途（purpose）・時間（dateTime）・地域（spatial）を
 * 判定し、prohibition に合致すれば `deny`（提示拒否）、obligation 未充足は `warn`（警告のみ）。
 * permission が定義され、いずれの permission にも合致しない利用は `deny` とする（allowlist 解釈）。
 * 規則集合の評価は `policy-eval.ts`、制約 1 件の評価は `odrl.ts` / `operators.ts` に切り出す。
 * 未知語彙（未知 `leftOperand` / 対応外 `operator` / 対象外 `action`）は既定 fail-open で、
 * `ToUCheckOptions` により fail-closed へ opt-in できる。
 *
 * セキュリティ: 例外 message / context に VC 本文（ToU の値）を含めない。
 */

import { ErrorCodes, VericertsError } from '../../errors.js';
import { ownProperty } from '../../prototype-safety/own-property.js';
import type { VerifiableCredential } from '../vc/vc.js';
import { isRecord, type ToURestriction, type UsageContext } from './odrl.js';
import {
  evaluateObligations,
  evaluatePermissions,
  evaluateProhibitions,
  type PolicyAccumulator,
  type ResolvedPolicies,
  type ToUViolation,
} from './policy-eval.js';
import { collectRules } from './rules.js';
import type { TermsOfUseEntry, ToUCheckOptions } from './types.js';

export type { ToURestriction, UsageContext } from './odrl.js';
export type { ToUViolation } from './policy-eval.js';
export type { ToUCheckOptions, UnknownVocabularyPolicy } from './types.js';

/** `checkTermsOfUse` の結果。 */
export interface ToUCheckResult {
  /** deny 違反が無ければ true。 */
  readonly compliant: boolean;
  /** 違反項目（deny / warn）。 */
  readonly violations: ToUViolation[];
  /** 警告メッセージ（warn 違反の要約）。 */
  readonly warnings: string[];
  /** ToU から抽出した利用制限。 */
  readonly restrictions: ToURestriction[];
}

/** `validateTermsOfUseOnPresentation` の結果。 */
export interface VPValidationResult {
  /** VP 内全 VC が compliant なら true（1 件でも deny があれば false）。 */
  readonly compliant: boolean;
  /** VC 毎の ToU 判定結果。 */
  readonly perCredential: Array<{ vcId: string; tou: ToUCheckResult }>;
}

/** VC の `termsOfUse`（object | object[] | undefined）をエントリ配列へ正規化する。 */
function collectEntries(tou: VerifiableCredential['termsOfUse']): TermsOfUseEntry[] {
  if (tou === undefined) {
    return [];
  }
  const list = Array.isArray(tou) ? tou : [tou];
  return list.filter((e): e is TermsOfUseEntry => isRecord(e));
}

/**
 * VC の `termsOfUse` を利用文脈に対して評価し、遵守状況を判定する。
 *
 * 評価規則:
 * - prohibition に合致（constraint 成立）した利用は違反（既定 `deny`）。
 * - permission が 1 件以上定義され、いずれの permission 制約にも合致しない利用は `deny`（allowlist）。
 * - obligation が未充足（constraint 不成立）なら `warn`。
 * ルールの `severity` 指定があればそれで上書きする。deny 違反が 1 件も無ければ `compliant=true`。
 *
 * 既定は fail-open で、未知の `leftOperand` は「制約を課さない」として通し、`use` / `present` / `*`
 * 以外の `action` を持つルールは無視する。`options` に `fail-closed` を指定すると、これらを
 * 「判定不能」とみなして `deny` 違反を立てる。`options` 省略時の挙動は
 * 本オプション導入前と同一で、既存の呼び出し側には影響しない。
 *
 * @throws `UsageContext.at` が不正な ISO の場合（`VC_SCHEMA_INVALID` 3002）。VC 本文由来の
 *         `rightOperand` の不正は例外にせず評価不能として扱う（`compareDateTime` 参照）。
 *         termsOfUse エントリが object でない場合は throw せず読み飛ばす。
 *
 * @experimental 公開直後は挙動・シグネチャが変わり得る（v1.0 で `@stable` 昇格予定）。
 */
export async function checkTermsOfUse(
  vc: VerifiableCredential,
  context: UsageContext,
  options?: ToUCheckOptions,
): Promise<ToUCheckResult> {
  const policies: ResolvedPolicies = {
    constraint:
      (options === undefined
        ? undefined
        : ownProperty<ResolvedPolicies['constraint']>(options, 'unknownConstraint')) ?? 'fail-open',
    action:
      (options === undefined
        ? undefined
        : ownProperty<ResolvedPolicies['action']>(options, 'unknownAction')) ?? 'fail-open',
  };
  const out: PolicyAccumulator = { violations: [], restrictions: [] };

  for (const entry of collectEntries(
    ownProperty<VerifiableCredential['termsOfUse']>(vc, 'termsOfUse'),
  )) {
    const prohibition = ownProperty<TermsOfUseEntry['prohibition']>(entry, 'prohibition');
    const permission = ownProperty<TermsOfUseEntry['permission']>(entry, 'permission');
    const obligation = ownProperty<TermsOfUseEntry['obligation']>(entry, 'obligation');
    const entryId = ownProperty<TermsOfUseEntry['id']>(entry, 'id');
    evaluateProhibitions(collectRules(prohibition), entryId, context, policies, out);
    evaluatePermissions(collectRules(permission), entryId, context, policies, out);
    evaluateObligations(collectRules(obligation), entryId, context, policies, out);
  }

  const compliant = !out.violations.some((v) => v.severity === 'deny');
  const warnings = out.violations.filter((v) => v.severity === 'warn').map((v) => v.message);
  return { compliant, violations: out.violations, warnings, restrictions: out.restrictions };
}

/** VP（object）から各 VC を抽出する。`verifiableCredential` は object | object[] | undefined。 */
function extractVcsFromVp(vp: object): VerifiableCredential[] {
  if (!isRecord(vp)) {
    return [];
  }
  const raw = ownProperty<unknown>(vp, 'verifiableCredential');
  if (raw === undefined) {
    return [];
  }
  const list = Array.isArray(raw) ? raw : [raw];
  return list.filter((c): c is VerifiableCredential => isRecord(c));
}

/**
 * Verifier が受領した VP 内の各 VC について `termsOfUse` 遵守を判定する。
 *
 * VP を展開した各 VC に `checkTermsOfUse` を適用し、1 件でも deny 違反があれば VP 全体を
 * `compliant=false` とする。署名検証・JWT デコードは `verifyPresentation` の責務であり、本関数は
 * 展開済み VP object の ToU 評価のみを行う。引数の型は `string | object` だが、
 * 文字列（JWT）形式は `assertVpObject` で拒否する。
 *
 * @throws VP が文字列（未パース）の場合、および `UsageContext.at` が不正な ISO の場合（`VC_SCHEMA_INVALID` 3002）。VC 本文由来の
 *         `rightOperand` の不正は例外にせず評価不能として扱う（`compareDateTime` 参照）。
 *
 * @experimental 公開直後は挙動・シグネチャが変わり得る（v1.0 で `@stable` 昇格予定）。
 */
export async function validateTermsOfUseOnPresentation(
  vp: string | object,
  context: UsageContext,
  options?: ToUCheckOptions,
): Promise<VPValidationResult> {
  const vcs = extractVcsFromVp(assertVpObject(vp));
  const perCredential = await Promise.all(
    vcs.map(async (vc, i) => ({
      vcId: ownProperty<VerifiableCredential['id']>(vc, 'id') ?? `vc[${i}]`,
      tou: await checkTermsOfUse(vc, context, options),
    })),
  );
  const compliant = perCredential.every((entry) => entry.tou.compliant);
  return { compliant, perCredential };
}

/** VP が object であることを保証する（string 形式は非対応として拒否）。 */
export function assertVpObject(vp: string | object): object {
  if (typeof vp === 'string') {
    // JWT/文字列 VP のデコードは verifyPresentation の責務。ToU 評価は展開済み object を要求する。
    throw new VericertsError(ErrorCodes.VC_SCHEMA_INVALID);
  }
  return vp;
}
