/**
 * Trusted Issuer List の発行者 DID 索引と、索引越しの信頼判定。
 *
 * `isTrustedIssuer`（`trusted-issuer-list-store.ts`）は 1 回あたりリスト全エントリを線形走査する。
 * VP の内包 VC ごと・`type` ごとに呼ぶと「VC の種別数 × リストのエントリ数」になり、署名検証に失敗する
 * VC でも（攻撃者の VP だけで）数秒止まる。そこで VP の検証 1 回につきリストを発行者 DID で一度だけ
 * 索引化し、各 VC の判定は「その発行者のエントリ数 + エントリが宣言した種別数」だけを数える。
 * 数えた走査量は共有の `PresentationWorkBudget`（`trustScans`）に計上し、超過は fail-closed で拒否する。
 */

import {
  MAX_CREDENTIAL_TYPES,
  type PresentationWorkBudget,
  spendWork,
} from '../primitives/presentation-work-budget.js';
import { ownProperty } from '../prototype-safety/own-property.js';
import { entryIssuerId, isWithinValidity, trustedIssuersOf } from './trusted-issuer-list-store.js';
import type { TrustedIssuerEntry, TrustedIssuerList } from './types.js';

/** 発行者 DID → その DID を `id` に持つエントリ（リスト内の出現順）。 */
export type TrustedIssuerIndex = ReadonlyMap<string, readonly TrustedIssuerEntry[]>;

/** リストを発行者 DID で索引化する（O(エントリ数)。VP の検証 1 回につき 1 度だけ作る）。 */
export function buildTrustedIssuerIndex(list: TrustedIssuerList): TrustedIssuerIndex {
  const index = new Map<string, TrustedIssuerEntry[]>();
  for (const entry of trustedIssuersOf(list)) {
    const id = entryIssuerId(entry);
    if (id === undefined) {
      continue;
    }
    const bucket = index.get(id);
    if (bucket === undefined) {
      index.set(id, [entry]);
    } else {
      bucket.push(entry);
    }
  }
  return index;
}

/**
 * `types`（VC の種別）を重複排除して返す。相異なる種別が {@link MAX_CREDENTIAL_TYPES} を超える、または
 * 空なら `undefined`（種別を取り出せない扱い。種別で制限したエントリを信頼しない fail-closed）。
 * 件数に比例して走査量が増えないよう、超過を見つけた時点で打ち切る。
 */
function distinctTypes(types: readonly string[]): ReadonlySet<string> | undefined {
  const distinct = new Set<string>();
  for (const type of types) {
    distinct.add(type);
    if (distinct.size > MAX_CREDENTIAL_TYPES) {
      return undefined;
    }
  }
  return distinct.size === 0 ? undefined : distinct;
}

/**
 * 索引越しに「`issuerDid` を信頼するエントリが、`types` の種別・基準時刻 `atMs` で有効か」を判定する。
 *
 * 意味は `isTrustedIssuer` と同じ: 種別を取り出せない（`types` が空 / 上限超過）ときは `credentialTypes` で
 * 種別を制限したエントリを信頼せず、制限の無いエントリだけを照合する。制限のあるエントリは、
 * 宣言した種別のいずれかが `types` に含まれれば信頼する。
 *
 * 走査量はエントリごとに `1 + エントリの credentialTypes 数` を `budget` の `trustScans` に計上する
 * （`types` の件数には依存しない）。
 *
 * @param index {@link buildTrustedIssuerIndex} の結果。
 * @param issuerDid 判定する発行者 DID。
 * @param types VC の種別（重複・件数は問わない）。
 * @param atMs 基準時刻（エポックミリ秒）。有限でなければ `false`。
 * @param budget 走査量を計上する共有予算（省略時は計上しない）。
 */
export function isTrustedInIndex(
  index: TrustedIssuerIndex,
  issuerDid: string,
  types: readonly string[],
  atMs: number,
  budget: PresentationWorkBudget | undefined,
): boolean {
  if (!Number.isFinite(atMs)) {
    return false;
  }
  const distinct = distinctTypes(types);
  for (const entry of index.get(issuerDid) ?? []) {
    const credentialTypes = ownProperty<readonly string[]>(entry, 'credentialTypes');
    spendWork(budget, 'trustScans', 1 + (credentialTypes?.length ?? 0));
    const typeMatches =
      credentialTypes === undefined ||
      (distinct !== undefined && credentialTypes.some((type) => distinct.has(type)));
    if (typeMatches && isWithinValidity(entry, atMs)) {
      return true;
    }
  }
  return false;
}
