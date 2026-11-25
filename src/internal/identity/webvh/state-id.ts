/**
 * DID Document（`state`）の `id` に対する検証（portable を含む）。検証側（`./verify.ts`）と
 * 生成側（`./lifecycle-update.ts`）が同じ規則を使う。
 *
 * spec: DIF didwebvh v1.0「Read (Resolve)」6、「DID Portability」。
 * - `state.id` は bare な `did:webvh` で、SCID は**全版**で DID の SCID と一致する。
 * - host / path が変わる版（移動）は、portable が有効で、`alsoKnownAs` に直前の DID を含む。
 *
 * 例外メッセージ・`context` に DID 文字列を含めない。
 */

import { ErrorCodes, VericertsError } from '../../errors.js';
import { ownProperty } from '../../prototype-safety/own-property.js';
import type { DIDDocument } from '../did.js';
import { parseWebVh } from './did-url.js';

function invalid(): VericertsError {
  return new VericertsError(ErrorCodes.INVALID_DID);
}

/**
 * `state.id` を検証する: 文字列の `did:webvh` で、SCID が DID の SCID と一致すること。
 *
 * @returns `state.id` の host / path 部（`domain[:path...]`。移動の検出に使う）。
 * @throws 文字列でない・DID として不正・SCID が違う場合（VericertsError、code `2001`）。
 */
export function locationOfStateId(stateId: unknown, scid: string): string {
  if (typeof stateId !== 'string') {
    throw invalid();
  }
  const parsed = parseWebVh(stateId);
  if (parsed.scid !== scid) {
    throw invalid();
  }
  return [parsed.domain, ...parsed.pathSegments].join(':');
}

/**
 * `state.id` の host / path が変わる版（portable な移動）の条件を検証する: 直前の版で portable が有効で、`alsoKnownAs` に
 * 直前の DID を含む。
 *
 * @throws 条件を満たさない場合（VericertsError、code `2001`）。
 */
export function assertPortableMove(
  state: DIDDocument,
  previousPortable: boolean,
  previousStateId: string,
): void {
  const alsoKnownAs = ownProperty<unknown>(state, 'alsoKnownAs');
  if (!previousPortable || !Array.isArray(alsoKnownAs) || !alsoKnownAs.includes(previousStateId)) {
    throw invalid();
  }
}
