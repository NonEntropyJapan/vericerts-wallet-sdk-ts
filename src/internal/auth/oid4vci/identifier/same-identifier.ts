/**
 * 発行者 / AS の識別子（URL）の同一性比較（OID4VCI 1.0 §12.2.4 / RFC 8414 §3.3）。
 *
 * 比較は文字列の完全一致だが、末尾スラッシュの有無だけで正当な Metadata / Offer を落とさない
 * よう、両辺の末尾スラッシュを除いてから比べる。識別子の照合が経路ごとにずれると、片方の経路だけ
 * Metadata すり替え（mix-up）を許すため、照合規則を 1 か所に置く。
 */

import { trimTrailingSlashes } from '../../../primitives/trim-trailing-slashes.js';

/**
 * 2 つの識別子が（末尾スラッシュ正規化後に）完全一致するか。
 *
 * @param actual Metadata が名乗る識別子など、検証される側の値。
 * @param expected Offer / 取得に用いた識別子など、信頼の起点になる値。
 */
export function sameIdentifier(actual: string, expected: string): boolean {
  return trimTrailingSlashes(actual) === trimTrailingSlashes(expected);
}
