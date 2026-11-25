/**
 * (Q)EAA 受領時の Catalogue `issuerAllowList` 照合。
 */

import { ErrorCodes, VericertsError } from '../../../errors.js';
import type { AttestationCatalogueEntry } from '../../../eudi/pid/index.js';
import { ownProperty } from '../../../prototype-safety/own-property.js';

/**
 * Catalogue の `issuerAllowList` が定義されていれば、受領した VC の `iss` が一覧に含まれることを
 * 要求する。`undefined` は許可リスト無し（制約なし）、定義済みなら空配列は全拒否、`iss` が欠落・
 * 不一致なら 8020 `issuer_not_allowed` で fail-closed に拒否する。照合は完全一致（正規化しない）で、
 * 署名検証が鍵解決に使う `iss` と同じ値を見る。定義されているのに配列でない値は「許可リストを
 * 読めない」ので許可扱いにせず拒否する。
 *
 * @param entry 解決済みの Catalogue エントリ。
 * @param iss 受領した VC の `iss`（無ければ `undefined`）。
 * @throws 許可リスト外の Issuer の場合（VericertsError、code `8020`）。
 */
export function assertIssuerAllowed(
  entry: AttestationCatalogueEntry,
  iss: string | undefined,
): void {
  const allowList = ownProperty<unknown>(entry, 'issuerAllowList');
  if (allowList === undefined) {
    return;
  }
  if (!Array.isArray(allowList) || iss === undefined || !allowList.includes(iss)) {
    throw new VericertsError(ErrorCodes.CREDENTIAL_REQUEST_FAILED, {
      context: { reason: 'issuer_not_allowed' },
    });
  }
}
