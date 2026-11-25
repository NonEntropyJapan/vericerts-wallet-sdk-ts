/**
 * ペルソナ一覧のソート（`PersonaManager.listPersonas` から分離した純粋関数）。
 */

import { ownProperty } from '../prototype-safety/own-property.js';
import type { PersonaMetadata, PersonaSortKey } from './types.js';

/**
 * 一覧をソートキー・方向に従って安定的に並べ替える。
 *
 * `label` でのソート時、label 未設定（undefined）は空文字として比較する。
 *
 * @param items ソート対象（破壊的に変更しないようコピーを並べ替える）。
 * @param sortBy ソートキー。
 * @param order 昇順 / 降順。
 * @returns 並べ替えた新しい配列。
 */
export function sortPersonas(
  items: PersonaMetadata[],
  sortBy: PersonaSortKey,
  order: 'asc' | 'desc',
): PersonaMetadata[] {
  const direction = order === 'desc' ? -1 : 1;
  return [...items].sort((a, b) => {
    if (sortBy === 'label') {
      return (
        (ownProperty<string>(a, 'label') ?? '').localeCompare(
          ownProperty<string>(b, 'label') ?? '',
        ) * direction
      );
    }
    return (a[sortBy] - b[sortBy]) * direction;
  });
}
