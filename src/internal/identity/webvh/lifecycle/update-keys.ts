/**
 * did:webvh の生成・更新時に `updateKeys` / `nextKeyHashes` を検証する共有ガード。
 *
 * `verifyChain` は `updateKeys` の各要素を Ed25519 Multikey として厳密に解釈する（`proof.ts`）。
 * 生成側が緩いと、署名不能・更新不能な DID Log を作れてしまう。`updateKeys` は SCID に焼き付き、
 * 更新でも以降の版の署名権限を恒久的に決めるため、公開後には復旧できない。
 *
 * 例外メッセージ・`context` に鍵文字列を含めない。
 */

import { ErrorCodes, VericertsError } from '../../../errors.js';
import { MAX_KEYS_PER_ENTRY, rejectDidLogOversized } from '../limits.js';
import { isSha256MultihashBase58 } from '../multihash.js';
import { ed25519PublicKeyFromMultikey } from '../proof.js';

/**
 * `updateKeys` を検証し、写しを返す。非空配列で、各要素が Ed25519 Multikey であること。
 *
 * @param keys 呼び出し側指定の updateKeys（型は保証されない）。
 * @returns 検証済みの写し。
 * @throws 配列でない・空・件数が `MAX_KEYS_PER_ENTRY` 超・Ed25519 Multikey でない要素を含む場合（VericertsError、code `2001`）。
 */
export function assertUpdateKeys(keys: unknown): string[] {
  if (!Array.isArray(keys) || keys.length === 0) {
    throw new VericertsError(ErrorCodes.INVALID_DID);
  }
  // 検証側（`verifyChain`）が拒否する件数のログを作らせない。
  rejectDidLogOversized(keys.length, MAX_KEYS_PER_ENTRY);
  const copy: unknown[] = [...keys];
  for (const key of copy) {
    if (typeof key !== 'string') {
      throw new VericertsError(ErrorCodes.INVALID_DID);
    }
    ed25519PublicKeyFromMultikey(key);
  }
  return copy as string[];
}

/**
 * `nextKeyHashes` を検証し、写しを返す。文字列配列で、各要素が sha-256 multihash の base58btc 表記（`z` なし、46 文字）であること。
 * 空配列は事前コミットの明示解除として許す。
 *
 * @param hashes 呼び出し側指定の nextKeyHashes（型は保証されない）。
 * @returns 検証済みの写し。
 * @throws 配列でない・件数が `MAX_KEYS_PER_ENTRY` 超・multihash 形式でない要素を含む場合（VericertsError、code `2001`）。
 */
export function assertNextKeyHashes(hashes: unknown): string[] {
  if (!Array.isArray(hashes)) {
    throw new VericertsError(ErrorCodes.INVALID_DID);
  }
  rejectDidLogOversized(hashes.length, MAX_KEYS_PER_ENTRY);
  const copy: unknown[] = [...hashes];
  if (!copy.every(isSha256MultihashBase58)) {
    throw new VericertsError(ErrorCodes.INVALID_DID);
  }
  return copy as string[];
}
