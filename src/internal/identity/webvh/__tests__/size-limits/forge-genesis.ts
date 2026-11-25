/**
 * 生成側の上限を迂回した偽造ログのフィクスチャ（size-limits テスト専用）。
 */

import { computeScid, deriveVersionId, SCID_PLACEHOLDER, type WebVhLogEntry } from '../../codec.js';
import type { TestKey } from '../webvh-fixtures.js';

/**
 * 生成側の上限（`createDidWebVh` の `assertLogAppendWithinLimits`）を通さずに、`padding` 文字の service を持つ
 * 初版を作る。**検証側**の上限が、生成側を迂回して作られた巨大ログを拒否することを確かめるための偽造用。
 */
export function forgeGenesisWithPadding(
  keys: readonly TestKey[],
  padding: number,
  domain = 'vericerts.io',
): { did: string; logEntry: WebVhLogEntry } {
  const versionTime = new Date(Date.now() - 60_000).toISOString();
  const updateKeys = keys.map((k) => k.multikey);
  const stateFor = (id: string) => ({
    '@context': ['https://www.w3.org/ns/did/v1'],
    id,
    verificationMethod: [],
    authentication: [],
    assertionMethod: [],
    service: [{ id: '#a', type: 'X', serviceEndpoint: 'x'.repeat(padding) }],
  });
  const parametersFor = (scid: string) => ({ method: 'did:webvh:1.0', scid, updateKeys });
  const placeholderEntry = {
    versionId: SCID_PLACEHOLDER,
    versionTime,
    parameters: parametersFor(SCID_PLACEHOLDER),
    state: stateFor(`did:webvh:${SCID_PLACEHOLDER}:${domain}`),
  };
  const scid = computeScid(placeholderEntry);
  const did = `did:webvh:${scid}:${domain}`;
  const draft = {
    versionId: '',
    versionTime,
    parameters: parametersFor(scid),
    state: stateFor(did),
  } as WebVhLogEntry;
  return { did, logEntry: { ...draft, versionId: deriveVersionId(draft, 1, scid) } };
}
