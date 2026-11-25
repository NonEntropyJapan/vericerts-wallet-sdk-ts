/**
 * 呼び出し側が渡す Dashboard ログエントリを、chain 検証が読める own の写しへ畳む。
 *
 * `verifyDashboardLogChain` / `resolveDeletionRecords` は公開 API で、`DashboardLog.list` の戻り値（null プロトタイプで
 * 復号済み）だけでなく、手組み・別経路で復元した素のオブジェクトも受ける。`id` / `type` / `recordedAt` / `prevHash` /
 * `signature` は型上必須でも、それを**省略した**エントリを `Object.prototype` の汚染下で素読みすると継承値を拾い、
 * 署名対象との照合（`type` / `recordedAt` / `prevHash`）や連番・chain の判定が攻撃者の選んだ値で通る。
 *
 * 写しは null プロトタイプで 6 キーを**必ず own として持つ**（省略・型違反は、どの判定にも一致しない値に倒す）。
 * したがって下流の素読みは継承元を持たず、汚染値を拾わない。型が合わないキーは fail-closed に倒す:
 * `id` / `signature` / `type` / `recordedAt` は空文字（`malformedId` / `signatureInvalid` として報告される）、
 * `prevHash` は `undefined`（文字列にも `null` にも一致しない）、`payload` は空オブジェクト。
 */

import { ownProperty } from '../../prototype-safety/own-property.js';
import type { DashboardLogEntry } from '../types.js';

function ownString(entry: object, key: string): string {
  const value = ownProperty<unknown>(entry, key);
  return typeof value === 'string' ? value : '';
}

/** エントリ 1 件を own の写しへ畳む。`entry` が非オブジェクトなら全キーが fail-closed 値の写しになる。 */
export function snapshotDashboardLogEntry(entry: DashboardLogEntry): DashboardLogEntry {
  const source: object = typeof entry === 'object' && entry !== null ? entry : {};
  const payload = ownProperty<unknown>(source, 'payload');
  const prevHash = ownProperty<unknown>(source, 'prevHash');
  const copy = Object.create(null) as Record<string, unknown>;
  copy.id = ownString(source, 'id');
  copy.type = ownString(source, 'type');
  copy.recordedAt = ownString(source, 'recordedAt');
  copy.payload = typeof payload === 'object' && payload !== null ? payload : {};
  copy.prevHash = prevHash === null || typeof prevHash === 'string' ? prevHash : undefined;
  copy.signature = ownString(source, 'signature');
  return copy as unknown as DashboardLogEntry;
}
