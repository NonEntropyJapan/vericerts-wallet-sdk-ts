/**
 * Dashboard ログの `LogFilter` 判定ロジック（purgeDashboardLog）。
 *
 * `purgeDashboardLog` / `exportDashboardLog` が共有するエントリ絞り込み述語を、ログ storage 本体
 * （`DashboardLog`）から分離する（storage の関心事とフィルタ判定の関心事を切り離し、双方を薄く保つ）。
 * 判定は副作用を持たない純関数で、単体テスト可能。
 */

import { parseIsoDateTimeMs } from '../cache/iso-datetime.js';
import { ErrorCodes, VericertsError } from '../errors.js';
import { ownProperty } from '../prototype-safety/own-property.js';
import { canonicalizeRpIdentifier } from '../rp-identifier.js';
import type { DashboardLogEntry, LogFilter } from './types.js';

/**
 * `filter.olderThan` が厳格な ISO 8601 日時（オフセット必須。`parseIsoDateTimeMs`）であることを検証する。
 *
 * 辞書順比較では `'yesterday'` が全エントリに一致して `purgeDashboardLog`（不可逆）が全件削除になるため、
 * 不正値は何も読み書きする前に拒否する（fail-closed）。`DashboardLog` の各入口（purge / exportLog /
 * deleteLogEntries）が storage に触れる前に呼ぶ。
 *
 * @param filter 検証対象のフィルタ（省略可）。
 * @throws `olderThan` が ISO 8601 日時として解釈できない場合（VericertsError、code `3002`）。
 */
export function assertValidLogFilter(filter?: LogFilter): void {
  const { olderThan } = readFilter(filter);
  if (olderThan !== undefined && Number.isNaN(parseIsoDateTimeMs(olderThan))) {
    throw new VericertsError(ErrorCodes.VC_SCHEMA_INVALID);
  }
}

/** `LogFilter` を own プロパティだけから読み出した値（未指定は `undefined`）。 */
interface ReadFilter {
  readonly olderThan: string | undefined;
  readonly types: readonly string[] | undefined;
  readonly rpIdentifier: string | undefined;
}

/**
 * 呼び出し側が渡す `filter` を入口で一度だけ own 限定読みする。`filter.types` 等の直接読みは
 * プロトタイプ鎖を辿るため、`Object.prototype` 汚染下で「全件対象」の `purge({})` が汚染された `types` を
 * 継承して一部しか消さない。
 */
function readFilter(filter?: LogFilter): ReadFilter {
  if (filter === undefined) {
    return { olderThan: undefined, types: undefined, rpIdentifier: undefined };
  }
  return {
    olderThan: ownProperty<string>(filter, 'olderThan'),
    types: ownProperty<readonly string[]>(filter, 'types'),
    rpIdentifier: ownProperty<string>(filter, 'rpIdentifier'),
  };
}

/**
 * エントリが `LogFilter` の条件をすべて満たすか（AND 条件）を判定する。
 *
 * `filter` 省略時、または全フィールド未指定時は常に一致（全エントリ対象）。指定された条件は以下:
 * - `olderThan`: `entry.recordedAt` が当該 ISO 8601 日時より前（`<`）。エポックミリ秒の数値比較で、
 *   オフセット付き（`+09:00`）やミリ秒なしの表記も正規化して比較する。どちらかが解釈不能なら不一致。
 * - `types`: `entry.type` が配列に含まれる。
 * - `rpIdentifier`: payload 直下の `rpIdentifier`・`clientId`（`presentation` の RP）、または
 *   `scope.rpIdentifier`（`consentRevoked`）が一致する。比較は `canonicalizeRpIdentifier` で両辺を正規化する。
 *
 * @param entry 判定対象のエントリ。
 * @param filter 絞り込み条件（省略時は常に一致）。
 * @returns すべての条件を満たせば true。
 */
export function entryMatchesFilter(entry: DashboardLogEntry, filter?: LogFilter): boolean {
  const { olderThan, types, rpIdentifier } = readFilter(filter);
  if (
    olderThan !== undefined &&
    // NaN との比較は常に false となり、解釈不能な値は一致しない（fail-closed）。
    !(parseIsoDateTimeMs(entry.recordedAt) < parseIsoDateTimeMs(olderThan))
  ) {
    return false;
  }
  if (types !== undefined && !types.includes(entry.type)) {
    return false;
  }
  if (rpIdentifier !== undefined && !payloadReferencesRp(entry.payload, rpIdentifier)) {
    return false;
  }
  return true;
}

/** `filter` が全エントリに一致する（省略、または全フィールド未指定）か。 */
export function isUnrestrictedFilter(filter?: LogFilter): boolean {
  const { olderThan, types, rpIdentifier } = readFilter(filter);
  return olderThan === undefined && types === undefined && rpIdentifier === undefined;
}

/** RP 識別子を正規化する。正規化できない値（保存済みの不正値など）は原文のまま比較する。 */
function canonicalOrRaw(value: string): string {
  try {
    return canonicalizeRpIdentifier(value);
  } catch {
    return value;
  }
}

/**
 * エントリ payload が指定 RP を参照するかを判定する。
 *
 * payload 直下の `rpIdentifier`、`presentation` が RP を入れる `clientId`、または `scope.rpIdentifier`
 * （`consentRevoked`）に RP 識別子を持つため各形を確認する。表記ゆれ（大文字小文字・末尾 `/`）で
 * 取りこぼさないよう両辺を正規化して比較する。
 */
function payloadReferencesRp(
  payload: Readonly<Record<string, unknown>>,
  rpIdentifier: string,
): boolean {
  const target = canonicalOrRaw(rpIdentifier);
  const scope = ownProperty<unknown>(payload, 'scope');
  const candidates = [
    ownProperty<unknown>(payload, 'rpIdentifier'),
    ownProperty<unknown>(payload, 'clientId'),
    typeof scope === 'object' && scope !== null
      ? ownProperty<unknown>(scope, 'rpIdentifier')
      : undefined,
  ];
  return candidates.some((value) => typeof value === 'string' && canonicalOrRaw(value) === target);
}
