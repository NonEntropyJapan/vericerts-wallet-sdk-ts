/**
 * v1.0 のテストが共有するログの組み立てヘルパ（署名済みログを作り、`globalThis.fetch` モックで解決する）。
 */

import { ed25519 } from '@noble/curves/ed25519.js';
import { ErrorCodes, VericertsError } from '../../../../errors.js';
import type { DIDDocument } from '../../../did.js';
import type { WebVhLogEntry, WebVhParameters } from '../../codec.js';
import { deriveVersionId, nextVersionTime, versionNumberOf } from '../../codec.js';
import {
  createDidWebVh,
  createWebVhWitnessProof,
  resolveDidWebVhWithMetadata,
  updateDidWebVh,
} from '../../method-webvh.js';
import { generateKey, mockFetchOnce, signEntry, type TestKey, toJsonl } from '../webvh-fixtures.js';

export const INVALID_DID = new VericertsError(ErrorCodes.INVALID_DID);

/** 最小の DID Document（`id` だけ差し替える）。 */
export function stateOf(did: string, extra: Record<string, unknown> = {}): DIDDocument {
  return {
    '@context': ['https://www.w3.org/ns/did/v1'],
    id: did,
    verificationMethod: [],
    authentication: [],
    assertionMethod: [],
    ...extra,
  } as DIDDocument;
}

/** 署名済みの初版（`createDidWebVh`）と鍵を作る。 */
export function signedGenesis(options: Partial<Parameters<typeof createDidWebVh>[0]> = {}) {
  const key = generateKey();
  const { did, logEntry } = createDidWebVh({
    domain: 'vericerts.io',
    updateKeys: [key.multikey],
    ...options,
  });
  return { key, did, genesis: signEntry(logEntry, key) };
}

/**
 * `parameters` を指定どおり（省略したキーも省略のまま）にして、versionId を再計算した次版を作る（署名前）。
 * ビルダー（`updateDidWebVh`）が拒否する不正なログを作り、検証側の拒否を確かめるための偽造用。
 */
export function forgeNext(
  previous: WebVhLogEntry,
  state: DIDDocument,
  parameters: WebVhParameters,
  versionTime = nextVersionTime(previous.versionTime),
): WebVhLogEntry {
  const draft: WebVhLogEntry = { versionId: '', versionTime, parameters, state };
  return {
    ...draft,
    versionId: deriveVersionId(draft, versionNumberOf(previous.versionId) + 1, previous.versionId),
  };
}

/** 署名済みログを fetch モックに載せて解決する。 */
export function resolveLog(
  did: string,
  log: readonly WebVhLogEntry[],
  options?: Parameters<typeof resolveDidWebVhWithMetadata>[1],
) {
  mockFetchOnce(toJsonl(log));
  return resolveDidWebVhWithMetadata(did, options);
}

/** 鍵 `key` で署名した、`updateDidWebVh` 由来の次版。 */
export function appendSigned(
  log: readonly WebVhLogEntry[],
  key: TestKey,
  options: Partial<Parameters<typeof updateDidWebVh>[0]> = {},
): WebVhLogEntry {
  const last = log[log.length - 1] as WebVhLogEntry;
  return signEntry(updateDidWebVh({ previousLog: log, state: { ...last.state }, ...options }), key);
}

/** witness（Ed25519 の did:key）のテスト鍵。 */
export function witnessKey(): { key: TestKey; id: string } {
  const key = generateKey();
  return { key, id: `did:key:${key.multikey}` };
}

/** 検証用の witness proof（`createWebVhWitnessProof` と同じ署名対象を、テスト鍵の署名で作る）。 */
export function witnessProofFor(versionId: string, witness: { key: TestKey; id: string }) {
  return createWebVhWitnessProof(versionId, {
    id: witness.id,
    sign: (hashData) => ed25519.sign(hashData, witness.key.secretKey),
  });
}

/** `did.jsonl` と `did-witness.json` を URL ごとに返す fetch モックを置く。`witnessText` が `undefined` なら 404。取得した URL を返す。 */
export function mockWitnessHost(
  log: readonly WebVhLogEntry[],
  witnessText: string | undefined,
): string[] {
  const requested: string[] = [];
  globalThis.fetch = (async (input: string | URL | Request) => {
    const url =
      typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;
    requested.push(url);
    const isWitness = url.endsWith('/did-witness.json');
    const body = isWitness ? witnessText : toJsonl(log);
    const response =
      body === undefined
        ? new Response('not found', { status: 404 })
        : new Response(body, {
            status: 200,
            headers: { 'content-type': isWitness ? 'application/json' : 'application/jsonl' },
          });
    Object.defineProperty(response, 'url', { value: url, configurable: true });
    return response;
  }) as unknown as typeof fetch;
  return requested;
}

/** {@link mockWitnessHost} の fetch モックを置き、解決する。 */
export function resolveWithWitnessFile(
  did: string,
  log: readonly WebVhLogEntry[],
  witnessText: string | undefined,
  options?: Parameters<typeof resolveDidWebVhWithMetadata>[1],
  scope?: Parameters<typeof resolveDidWebVhWithMetadata>[2],
) {
  const requested = mockWitnessHost(log, witnessText);
  return { requested, result: resolveDidWebVhWithMetadata(did, options, scope) };
}
