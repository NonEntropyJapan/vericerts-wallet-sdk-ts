/**
 * VC の親エッジ抽出と関係種別ごとの失効伝搬の意味論。
 *
 * `verify.ts` のチェーン走査から使う純粋関数群。VC 本文に現れる 4 つの親エッジフィールド
 * （`derivedFrom` / `basedOn` / `supersedes` / `amends`）を `ChainRelation` 付きのエッジ列へ正規化する。
 *
 * セキュリティ: 例外 message / context に VC 本文・親 ID を含めない。
 */

import { ErrorCodes, VericertsError } from '../../errors.js';
import { chainTooLarge } from '../../primitives/presentation-work-budget.js';
import { isNonEmptyString } from '../../prototype-safety/non-empty-string.js';
import { ownProperty } from '../../prototype-safety/own-property.js';
import type { VerifiableCredential } from '../vc/vc.js';
import { MAX_CHAIN_PARENT_EDGES } from './limits.js';
import type { ChainRelation } from './types.js';

/** 親エッジ 1 本（子 → 親）。 */
export interface ParentEdge {
  /** 親 VC の ID。 */
  readonly id: string;
  /** このエッジの関係種別。 */
  readonly relation: ChainRelation;
}

/**
 * 親の失効を子へ伝搬する関係種別。
 *
 * `basedOn`（参考に過ぎない）と `supersedes`（親は論理的に廃止済み）は、親が失効しても子の有効性に
 * 影響しない。伝搬しない場合でも親の失効自体は警告として結果に残す。
 */
const PROPAGATING_RELATIONS: ReadonlySet<ChainRelation> = new Set<ChainRelation>([
  'derivedFrom',
  'amends',
]);

/** 関係種別が失効伝搬の対象かを返す。 */
export function propagatesRevocation(relation: ChainRelation): boolean {
  return PROPAGATING_RELATIONS.has(relation);
}

/** VC 本文の親エッジフィールドと関係種別の対応（走査順を兼ねる）。 */
const EDGE_FIELDS: ReadonlyArray<{
  readonly field: 'derivedFrom' | 'supersedes' | 'amends' | 'basedOn';
  readonly relation: ChainRelation;
}> = [
  { field: 'derivedFrom', relation: 'derivedFrom' },
  { field: 'supersedes', relation: 'supersedes' },
  { field: 'amends', relation: 'amends' },
  { field: 'basedOn', relation: 'basedOn' },
];

/**
 * 親 ID の宣言（`string | string[]`）を空でない文字列 ID の配列へ正規化する。
 *
 * `undefined` は「宣言なし」。それ以外で `string` / `string[]` に正規化できない値（object・数値・
 * 空文字・非文字列要素を含む配列など）を黙って捨てると、親が一切走査されず失効した親を持つチェーンが
 * `valid: true` になる（検証失敗の黙殺）。親を解決できないのと同じ `4052` で拒否する。
 *
 * @throws 正規化できない値の場合（VericertsError、code `4052`）、配列が `MAX_CHAIN_PARENT_EDGES` を超える場合（`4051`）。
 */
function normalizeIds(value: unknown): string[] {
  if (value === undefined) {
    return [];
  }
  if (isNonEmptyString(value)) {
    return [value];
  }
  if (Array.isArray(value) && value.length > MAX_CHAIN_PARENT_EDGES) {
    // 要素を 1 つずつ検査・走査する前に、巨大な親配列を件数だけで拒否する。
    throw chainTooLarge();
  }
  if (Array.isArray(value) && value.every(isNonEmptyString)) {
    return value;
  }
  throw new VericertsError(ErrorCodes.CHAIN_PARENT_UNRESOLVABLE);
}

/**
 * VC の親エッジをすべて列挙する。
 *
 * 走査順は `derivedFrom` → `supersedes` → `amends` → `basedOn`。
 *
 * 重複排除は **`(関係種別, 親 ID)` の組**で行い、親 ID だけでは行わない。同じ親を複数の関係で
 * 宣言した VC（例: `supersedes` と `amends` の両方で同じ親を指す）を ID で先勝ち dedup すると、
 * 非伝搬の関係だけが残って伝搬する関係が黙って捨てられ、失効が伝搬しなくなる（fail-open）。
 * 失効伝搬は経路ごとに判定し、伝搬経路が 1 本でもあれば伝搬する。各ノードの解決・評価は走査側でメモ化する。
 *
 * 4 フィールドは `ownProperty` で **own 限定**に読む。プロトタイプ鎖を辿ると、これらを一切
 * 宣言していない単発 VC が `Object.prototype` の汚染値由来の親エッジを持つと誤判定される。
 */
export function parentEdges(vc: VerifiableCredential): ParentEdge[] {
  const edges: ParentEdge[] = [];
  const seen = new Set<string>();
  for (const { field, relation } of EDGE_FIELDS) {
    for (const id of normalizeIds(ownProperty<unknown>(vc, field))) {
      // 完全に同一のエッジ（同じ関係で同じ親を 2 度書いた場合）だけを畳む。
      const key = `${relation}\u0000${id}`;
      if (seen.has(key)) {
        continue;
      }
      seen.add(key);
      edges.push({ id, relation });
      if (edges.length > MAX_CHAIN_PARENT_EDGES) {
        throw chainTooLarge();
      }
    }
  }
  return edges;
}
