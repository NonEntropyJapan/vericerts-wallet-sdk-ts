/**
 * DCQL 要件 1 件 × クレデンシャル 1 件の評価（`dcql.ts` の `evaluateDcql` / `findMatchingCredentialIndexes` が使う）。
 *
 * 一致した識別子を返し、`matchedClaims` は要件ごとに一度だけ作る。
 */

import type { WorkBudget } from '../../primitives/work-budget.js';
import { ownProperty } from '../../prototype-safety/own-property.js';
import { chargeDcqlWork } from './budget.js';
import type { DcqlClaim, DcqlCredential, DcqlMeta, QueryableCredential } from './dcql.js';
import { hasUnsupportedMetaMember } from './dcql-parse.js';

/** path 配列でクレーム object を辿る。途中が object でなければ `{ found: false }`。キー 1 件ごとに計上する。 */
function resolvePath(
  claims: Readonly<Record<string, unknown>>,
  path: readonly string[],
  budget: WorkBudget,
): { found: boolean; value: unknown } {
  chargeDcqlWork(budget, 1 + path.length);
  let current: unknown = claims;
  for (const key of path) {
    if (typeof current !== 'object' || current === null || Array.isArray(current)) {
      return { found: false, value: undefined };
    }
    const obj = current as Record<string, unknown>;
    if (!Object.hasOwn(obj, key)) {
      return { found: false, value: undefined };
    }
    current = obj[key];
  }
  return { found: true, value: current };
}

/**
 * VC の `type` が `type_values` の内側配列のいずれか 1 つを包含するか。
 *
 * OID4VP 1.0 の `jwt_vc_json` / `jwt_vc_json-ld` 向けメタ。内側配列は AND（全要素を含むこと）、
 * 外側は OR（いずれか 1 つを満たせばよい）。`type` を own 限定で読めない・配列でないクレデンシャルは
 * 一致させない（fail-closed。SD-JWT VC のように `type` を持たない形式はここで落ちる）。
 */
function matchesTypeValues(
  typeValues: readonly (readonly string[])[],
  claims: Readonly<Record<string, unknown>>,
  budget: WorkBudget,
): boolean {
  const credentialTypes = ownProperty<unknown>(claims, 'type');
  if (!Array.isArray(credentialTypes)) {
    return false;
  }
  for (const required of typeValues) {
    chargeDcqlWork(budget, required.length + credentialTypes.length);
    if (required.every((type) => credentialTypes.includes(type))) {
      return true;
    }
  }
  return false;
}

/** 値が `values` のいずれかに一致するか（プリミティブの厳密一致）。走査の前に要素数ぶんを計上する。 */
function valueMatches(value: unknown, values: readonly unknown[], budget: WorkBudget): boolean {
  chargeDcqlWork(budget, values.length);
  return values.some((candidate) => candidate === value);
}

/**
 * 1 要件 × 1 クレデンシャルの一致（識別子だけ）。`matchedClaims` は要件ごとに 1 つ共有するため持たない。
 */
export interface RequirementHit {
  readonly credentialId: string;
  readonly queryId: string;
}

/**
 * 単一 DCQL 要件に対し単一クレデンシャルがマッチするか評価する。
 *
 * **評価に使うメンバはすべて own 限定で読む**（`own-property.ts` の規約）。任意メンバ
 * （`meta` / `vct_values` / `claims` / `claim.values` / `credential.vct`）は「条件なし」が own
 * プロパティの**不在**で表されるので、鎖読みだと制約を持たない要件が継承値を条件に使う
 * （fail-open。回帰テスト `dcql-evaluate.proto-pollution.test.ts` 参照）。必須メンバ
 * （`format` / `id` / `credential.claims` / `claim.path`）も同じで、型が要求していても実体は
 * 外部由来の JSON（DCQL クエリは RP が組む）である。とくに `format` は両側を突き合わせるため、
 * **双方が own に持たなければ同じ継承値どうしが一致して検査が素通りする**。読めない必須メンバは
 * 「マッチしない」に倒す（fail-closed）。
 *
 * **要件側の `format` は読み直さず `evaluateDcql` が読んだ値を受け取る。** own の
 * アクセサプロパティは呼ばれるたびに別の値を返せるので、対応 format の検査（`SUPPORTED_FORMATS`）に
 * 通した値と突き合わせに使う値が同じ読み取りから来ていないと、「ゲートには対応 format を、
 * 比較には別の値を」返す要件を作れてしまう。own 限定・**1 回読み**で揃える。
 *
 * @param requiredFormat `evaluateDcql` が own 限定で読み、対応 format と確認済みの要件 format。
 */
export function evaluateCredentialRequirement(
  requirement: DcqlCredential,
  credential: QueryableCredential,
  requiredFormat: string,
  budget: WorkBudget,
): RequirementHit | undefined {
  // 要件 1 件 × VC 1 件の突き合わせは、format 不一致で即終了する場合も固定費 1 を計上する。
  chargeDcqlWork(budget, 1);
  if (requiredFormat !== ownProperty(credential, 'format')) {
    return undefined;
  }

  const meta = ownProperty<DcqlMeta>(requirement, 'meta') ?? {};
  // 評価できない制約（`type_values` 等）を無視すると無関係な VC が通る。パースを経ない手組みの
  // クエリでも fail-closed でマッチさせない。
  if (hasUnsupportedMetaMember(meta)) {
    return undefined;
  }
  // `vct_values` が指定されていれば（空配列でも）vct の一致を必須とする。空配列は「制約なし」ではない。
  const vctValues = ownProperty<readonly string[]>(meta, 'vct_values');
  const vct = ownProperty<string>(credential, 'vct');
  if (vctValues !== undefined) {
    chargeDcqlWork(budget, vctValues.length);
    if (vct === undefined || !vctValues.includes(vct)) {
      return undefined;
    }
  }

  const claimsObject = ownProperty<Readonly<Record<string, unknown>>>(credential, 'claims');
  const credentialId = ownProperty<string>(credential, 'id');
  const queryId = ownProperty<string>(requirement, 'id');
  if (claimsObject === undefined || credentialId === undefined || queryId === undefined) {
    return undefined;
  }

  // `type_values` が指定されていれば（空配列でも）`type` の包含を必須とする。
  const typeValues = ownProperty<readonly (readonly string[])[]>(meta, 'type_values');
  if (typeValues !== undefined && !matchesTypeValues(typeValues, claimsObject, budget)) {
    return undefined;
  }
  for (const claim of ownProperty<readonly DcqlClaim[]>(requirement, 'claims') ?? []) {
    const path = ownProperty<readonly string[]>(claim, 'path');
    if (path === undefined) {
      return undefined;
    }
    const { found, value } = resolvePath(claimsObject, path, budget);
    if (!found) {
      return undefined;
    }
    const values = ownProperty<readonly unknown[]>(claim, 'values');
    if (values !== undefined && !valueMatches(value, values, budget)) {
      return undefined;
    }
  }

  return { credentialId, queryId };
}

/**
 * 要件の `claims[].path` を `a.b.c` 形式へ連結した一覧（`CredentialMatch.matchedClaims`）。
 *
 * 一致した要件はすべての claim を満たしているので、一覧は要件だけで決まりクレデンシャルに依存しない。
 * 一致のたびに連結文字列を確保しない（保有数 H に比例して増えない）よう、要件ごとに 1 度だけ作って
 * その要件の全一致で共有する（変更不能）。
 */
export function matchedClaimPaths(requirement: DcqlCredential): readonly string[] {
  const paths: string[] = [];
  for (const claim of ownProperty<readonly DcqlClaim[]>(requirement, 'claims') ?? []) {
    paths.push((ownProperty<readonly string[]>(claim, 'path') ?? []).join('.'));
  }
  return Object.freeze(paths);
}
