/**
 * `IssuerModule.importEntries` の取り込み前検査。
 *
 * `exportEntries` で保存したデータは手編集・破損・別環境の取り違えで壊れうる。壊れたまま取り込むと
 * 「別 `vcId` が同じ idx を指して一方の失効が他方も失効させる」「範囲外 idx / 未知 purpose が黙って保持され
 * `setTokenStatus` の時点で初めて失敗する」運用事故になる。`StatusListManager.restore` が snapshot を
 * 検査するのと対に、取り込み側でも全件を検査し、違反が 1 件でもあれば何も取り込まずに拒否する。
 *
 * セキュリティ上の注意: 例外メッセージや `context` に vcId・インデックスを含めない。
 */

import { ErrorCodes, VericertsError } from '../../errors.js';
import { ownProperty } from '../../prototype-safety/own-property.js';
import type { StatusListManager } from '../token-status-list.js';
import type { IssuedStatusEntry, TokenStatusPurpose } from './issuer-module.js';

/** 検査済みの `vcId` → purpose → idx。 */
export type StatusIndexMap = Map<string, Map<TokenStatusPurpose, number>>;

/**
 * 取り込み対象を検査し、検査済みの `vcId` → purpose → idx を返す（`known` は変更しない）。
 *
 * 検査項目（いずれも違反は `3002`）:
 * - `vcId` が文字列、`indices` がオブジェクトであること。
 * - purpose が `statusLists` に設定済みの `TokenStatusPurpose` であること（未知 / 未設定リストは拒否）。
 * - idx が `0 <= idx < list.nextIndex`（割当済みの範囲。`nextIndex <= size`）の整数であること。
 * - 同一 `vcId` が異なる内容を持たないこと（既存との衝突・バッチ内の重複。同一内容は冪等に受理）。
 * - 同一 purpose で idx が他の `vcId`（既存 + 同一バッチ）と重複しないこと。
 *
 * @param entries 取り込む配列。
 * @param known 取り込み済みの `vcId` → purpose → idx。
 * @param statusLists purpose → Status List。
 * @returns 検査済みエントリ。
 * @throws 違反がある場合（VericertsError、code `3002`）。
 */
export function validateImportedEntries(
  entries: readonly IssuedStatusEntry[],
  known: ReadonlyMap<string, ReadonlyMap<TokenStatusPurpose, number>>,
  statusLists: Readonly<Partial<Record<TokenStatusPurpose, StatusListManager>>>,
): StatusIndexMap {
  const incoming: StatusIndexMap = new Map();
  // purpose → idx → 所有する vcId。既存エントリで初期化し、バッチ内の重複も同じ表で検出する。
  const owners = new Map<TokenStatusPurpose, Map<number, string>>();
  const claim = (purpose: TokenStatusPurpose, idx: number, vcId: string): boolean => {
    const byIdx = owners.get(purpose) ?? new Map<number, string>();
    owners.set(purpose, byIdx);
    const owner = byIdx.get(idx);
    byIdx.set(idx, vcId);
    return owner === undefined || owner === vcId;
  };
  for (const [vcId, indices] of known) {
    for (const [purpose, idx] of indices) {
      claim(purpose, idx, vcId);
    }
  }

  for (const entry of entries) {
    const vcId =
      typeof entry === 'object' && entry !== null ? ownProperty<unknown>(entry, 'vcId') : undefined;
    const rawIndices =
      typeof entry === 'object' && entry !== null
        ? ownProperty<unknown>(entry, 'indices')
        : undefined;
    if (typeof vcId !== 'string' || typeof rawIndices !== 'object' || rawIndices === null) {
      throw new VericertsError(ErrorCodes.VC_SCHEMA_INVALID);
    }
    const indices = new Map<TokenStatusPurpose, number>();
    for (const [key, idx] of Object.entries(rawIndices)) {
      const purpose = key as TokenStatusPurpose;
      const list = Object.hasOwn(statusLists, purpose) ? statusLists[purpose] : undefined;
      // `idx >= list.nextIndex` は未割当の idx。取り込むと後続の `issueVC` が同じ idx を別 VC に払い出し、
      // 一方の失効が無関係な VC も失効させる（`size` 未満でも割当カーソルを越えた idx は不整合）。
      if (list === undefined || !Number.isInteger(idx) || idx < 0 || idx >= list.nextIndex) {
        throw new VericertsError(ErrorCodes.VC_SCHEMA_INVALID);
      }
      indices.set(purpose, idx as number);
    }
    const existing = incoming.get(vcId) ?? known.get(vcId);
    if (existing !== undefined && !sameIndices(existing, indices)) {
      throw new VericertsError(ErrorCodes.VC_SCHEMA_INVALID);
    }
    for (const [purpose, idx] of indices) {
      if (!claim(purpose, idx, vcId)) {
        throw new VericertsError(ErrorCodes.VC_SCHEMA_INVALID);
      }
    }
    incoming.set(vcId, indices);
  }
  return incoming;
}

/** 2 つの `purpose → idx` 対応が同一内容か。 */
function sameIndices(
  a: ReadonlyMap<TokenStatusPurpose, number>,
  b: ReadonlyMap<TokenStatusPurpose, number>,
): boolean {
  return a.size === b.size && [...a].every(([purpose, idx]) => b.get(purpose) === idx);
}
