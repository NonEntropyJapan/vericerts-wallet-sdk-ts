/**
 * Type Metadata の `extends` 継承をマージする規則（draft-ietf-oauth-sd-jwt-vc §6）。
 *
 * 継承元（親）→ 継承先（子）の順に**浅くマージ**し、同名メンバは子を優先する。ただし `claims` は
 * 「親の定義を子が上書きしつつ、子に無い親の定義は残す」ため `path` をキーに統合する。
 * チェーンの走査・取得・キャッシュは `resolve.ts` が担い、本モジュールは 2 文書のマージ規則だけを持つ。
 */

import { ownProperty } from '../../../prototype-safety/own-property.js';
import type { SdJwtTypeMetadata } from './types.js';

/**
 * `claims` 配列を `path` キーで統合する（子が親を上書きし、子に無い親定義は残す）。
 *
 * `path` 配列を持たない要素は残さない（取得時の検査 `assertTypeMetadata` で弾いているが、
 * 無条件に積むと要素数が親子の合計で際限なく増えるため、マージ側でも落として総量を縛る）。
 */
function mergeClaims(
  parent: readonly unknown[] | undefined,
  child: readonly unknown[] | undefined,
): readonly unknown[] | undefined {
  if (parent === undefined) {
    return child;
  }
  if (child === undefined) {
    return parent;
  }
  /** `path` を安定キーへ直列化する。`path` 配列を持たない要素は `undefined`。 */
  const keyOf = (entry: unknown): string | undefined => {
    if (typeof entry !== 'object' || entry === null) {
      return undefined;
    }
    const path = (entry as Record<string, unknown>).path;
    return Array.isArray(path) ? JSON.stringify(path) : undefined;
  };
  const merged: unknown[] = [];
  const childKeys = new Set(child.map(keyOf).filter((k): k is string => k !== undefined));
  for (const entry of parent) {
    const key = keyOf(entry);
    // 子が同じ path を定義していれば親側は捨てる（子の定義で置き換わる）。
    if (key !== undefined && !childKeys.has(key)) {
      merged.push(entry);
    }
  }
  // 引数展開（`push(...child)`）は使わない。`claims` は取得先文書由来で要素数を攻撃者が制御でき、
  // V8 は 12.5 万引数程度で RangeError（Maximum call stack size exceeded）を投げる。
  // これは `VericertsError` ではないため呼び出し側の 3060 catch を素通りし、
  // 「取得失敗は例外を投げない」（FO-3）契約を破る。要素数に依存しないループで積む。
  for (const entry of child) {
    if (keyOf(entry) !== undefined) {
      merged.push(entry);
    }
  }
  return merged;
}

/**
 * 親 → 子の順に浅くマージする（同名メンバは子が優先）。
 *
 * マージ先は `Object.create(null)` で作る。リテラル展開（`{ ...parent, ...child }`）だと結果だけが
 * `Object.prototype` を継承し、取得時（`parseJsonWithoutPrototype`）の `null` プロトタイプ保証を失う。
 * `loadSchema` が読む `schema` / `schema_uri` を親子どちらも持たない場合に汚染値を拾い、攻撃者の
 * URL からスキーマを取得してしまう。own 列挙プロパティを写す意味論は展開と同一。
 */
export function mergeMetadata(
  parent: SdJwtTypeMetadata,
  child: SdJwtTypeMetadata,
): SdJwtTypeMetadata {
  const merged = Object.create(null) as Record<string, unknown>;
  Object.assign(merged, parent, child);
  const claims = mergeClaims(
    ownProperty<SdJwtTypeMetadata['claims']>(parent, 'claims'),
    ownProperty<SdJwtTypeMetadata['claims']>(child, 'claims'),
  );
  if (claims !== undefined) {
    merged.claims = claims;
  }
  // 子が schema / schema_uri のどちらかを持つ場合、親のもう一方が残ると併記になるため取り除く。
  if (ownProperty<unknown>(child, 'schema') !== undefined) {
    delete merged.schema_uri;
  } else if (ownProperty<unknown>(child, 'schema_uri') !== undefined) {
    delete merged.schema;
  }
  // 解決済みのため継承リンクは結果に残さない（`#integrity` は fetch.ts が受理していない）。
  delete merged.extends;
  return merged as unknown as SdJwtTypeMetadata;
}
