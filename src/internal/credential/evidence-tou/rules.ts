/**
 * termsOfUse エントリの `permission` / `prohibition` / `obligation` を規則配列へ正規化する
 * （`odrl.ts` から分離。ファイル行数上限のため）。
 */

import { isRecord } from './odrl.js';
import type { OdrlRule } from './types.js';

/**
 * 形状が規則を成さない値（文字列・数値・配列内の非オブジェクト要素）の代替。
 *
 * 黙って捨てると `unknownConstraint: 'fail-closed'` を指定していても `compliant: true` になる
 * （fail-open）ため、1 件の「評価不能な規則」として残す。評価側は `isMalformedRule` で判別し、
 * `fail-closed` なら `deny` 違反、`fail-open`（既定）なら従来どおり無視する。
 */
const MALFORMED_RULE: OdrlRule = Object.freeze({}) as OdrlRule;

/** `collectRules` が形状不正の値の代替として返した規則か。 */
export function isMalformedRule(rule: OdrlRule): boolean {
  return rule === MALFORMED_RULE;
}

/**
 * ODRL 規則（`permission` / `prohibition` / `obligation`）を `OdrlRule[]` へ正規化する。
 *
 * ODRL の JSON 表現は要素 1 件の集合を配列ではなく**単一オブジェクト**で書くことを許す
 * （`prohibition: { action: 'use' }`）。トップレベル `termsOfUse` は `collectEntries` が両形を受理し、
 * 規則内の `constraint` / `action` も単数を受理するため、規則だけ配列限定にすると単数の prohibition が
 * 黙って無視される。`undefined` / `null` は「規則なし」。配列でもオブジェクトでもない値と、配列内の
 * 非オブジェクト要素は形状不正の規則（`isMalformedRule`）として 1 件ずつ残す。
 */
export function collectRules(rules: unknown): OdrlRule[] {
  if (rules === undefined || rules === null) {
    return [];
  }
  const items: readonly unknown[] = Array.isArray(rules) ? rules : [rules];
  return items.map((item) => (isRecord(item) ? (item as OdrlRule) : MALFORMED_RULE));
}
