/**
 * DIF の did:webvh v1.0 公式相互運用テスト（`decentralized-identity/didwebvh-test-suite`）のベクタとの照合。
 * 出典・固定したコミット・範囲は `didwebvh-test-suite/README.md`。
 *
 * ベクタのログは `proof.challenge` を持たない（仕様に要件がないため）。SDK は `challenge` を要求しない（旧検査は
 * 外した。ログ位置の束縛は versionId を含む署名対象と entryHash の連鎖が担う）ので、ベクタのログは**署名し直さずそのまま**解決する:
 *
 * 1. ベクタの proof の署名入力が仕様（`eddsa-jcs-2022`）と byte 単位で一致すること（witness proof も）。
 * 2. 正のベクタは、`resolutionResult.json` の DID Document と解決メタデータに一致する。
 * 3. 負のベクタは、`invalid*` 相当（2001）で拒否される。
 */

import { afterEach, describe, expect, it } from 'bun:test';
import { sha256 } from '@noble/hashes/sha2.js';
import { verifyEd25519 } from '../../../../keymanager/ed25519.js';
import { multibaseBase58Decode, multibaseBase58Encode } from '../../../multibase.js';
import {
  canonicalize,
  entryWithoutProof,
  parseDidLog,
  type WebVhLogEntry,
  type WebVhProof,
} from '../../codec.js';
import { resolveDidWebVhWithMetadata } from '../../method-webvh.js';
import {
  documentHashOf,
  ed25519PublicKeyFromMultikey,
  eddsaJcs2022HashData,
  multikeyFromVerificationMethod,
  verifyEntryProof,
  verifyProofSignature,
} from '../../proof.js';
import { parseWitnessFile } from '../../witness/file.js';
import { verifyWitnessProof } from '../../witness/verify.js';
import { INVALID_DID, resolveWithWitnessFile } from '../v1/log-builders.js';
import { restoreFetch } from '../webvh-fixtures.js';
import { didOnlyVectors, loadCases, type VectorCase } from './vector-fixtures.js';

afterEach(() => {
  restoreFetch();
});

const CASES = loadCases();
const POSITIVE = CASES.filter((c) => !c.negative);
const NEGATIVE = CASES.filter((c) => c.negative);

/** 実装別の出力が持つ解決結果の書式差（`threshold` が数値・実装固有のメンバ）を除いて比べるメタデータのキー。 */
const COMPARED_METADATA = [
  'versionId',
  'created',
  'updated',
  'scid',
  'portable',
  'deactivated',
  'watchers',
];

/** 解決側が補う暗黙のサービス（仕様の「at risk」要件。SDK は補わない）。 */
const IMPLICIT_SERVICE = /#(files|whois)$/;

function proofsOf(entry: WebVhLogEntry): readonly WebVhProof[] {
  return entry.proof ?? [];
}

/** ログのエントリが現れる `state.id`（重複なし）。 */
function didsOf(entries: readonly WebVhLogEntry[]): string[] {
  return [...new Set(entries.map((entry) => entry.state.id))];
}

/** 解決して（witness は `did-witness.json` をそのまま使う）、DID Document とメタデータを返す。 */
function resolve(c: VectorCase, entries: readonly WebVhLogEntry[], did: string) {
  return resolveWithWitnessFile(did, entries, c.witnessText).result;
}

describe('公式ベクタ: proof の署名入力（eddsa-jcs-2022）が byte 単位で一致する', () => {
  it.each(
    POSITIVE.map((c) => [`${c.scenario}/${c.implementation}`, c] as const),
  )('%s: 全エントリの proof の署名が、SDK の署名入力で検証できる', (_name, c) => {
    const entries = parseDidLog(c.logText);
    for (const entry of entries) {
      const proof = proofsOf(entry)[0] as WebVhProof;
      const multikey = multikeyFromVerificationMethod(proof.verificationMethod);
      expect(verifyProofSignature(proof, documentHashOf(entryWithoutProof(entry)), multikey)).toBe(
        true,
      );
    }
  });

  it.each(
    POSITIVE.filter((c) => c.witnessText !== undefined).map(
      (c) => [`${c.scenario}/${c.implementation}`, c] as const,
    ),
  )('%s: did-witness.json の全 proof の署名が、{ versionId } の署名入力で検証できる', (_name, c) => {
    const items = parseWitnessFile(c.witnessText as string);
    expect(items.length).toBeGreaterThan(0);
    for (const item of items) {
      for (const proof of item.proof) {
        const id = `did:key:${multikeyFromVerificationMethod(proof.verificationMethod)}`;
        const budget = { remaining: 4 };
        expect(verifyWitnessProof(proof, item.versionId, new Set([id]), budget)).toBe(id);
      }
    }
  });
});

describe('公式ベクタ: 署名メッセージは SHA256(JCS(proofConfig)) ‖ SHA256(JCS(entry)) で、改変は拒否される', () => {
  const vector = POSITIVE.find((c) => c.scenario === 'basic-create' && c.implementation === 'ts');
  const entry = parseDidLog((vector as VectorCase).logText)[0] as WebVhLogEntry;
  const proof = proofsOf(entry)[0] as WebVhProof;
  const multikey = multikeyFromVerificationMethod(proof.verificationMethod);
  const allowed = new Set([multikey]);
  const sha = (value: unknown) => sha256(new TextEncoder().encode(canonicalize(value)));

  it('SDK の署名メッセージは、仕様の式を独立に計算した 64 バイトと一致し、その上で公式の署名が検証できる', () => {
    const { proofValue, ...proofConfig } = proof;
    const { proof: _proof, ...document } = entry;
    const expected = new Uint8Array([...sha(proofConfig), ...sha(document)]);

    const message = eddsaJcs2022HashData(proof, documentHashOf(entryWithoutProof(entry)));
    expect(message).toEqual(expected);
    expect(message.length).toBe(64);
    expect(
      verifyEd25519(
        message,
        multibaseBase58Decode(proofValue),
        ed25519PublicKeyFromMultikey(multikey),
      ),
    ).toBe(true);
    expect(() => verifyEntryProof(entry, allowed)).not.toThrow();
  });

  it('proofValue を 1 ビット変えると拒否される', () => {
    const signature = multibaseBase58Decode(proof.proofValue);
    for (const bit of [0, 7, signature.length * 8 - 1]) {
      const flipped = new Uint8Array(signature);
      flipped[bit >> 3] = (flipped[bit >> 3] as number) ^ (1 << (bit & 7));
      const tampered = {
        ...entry,
        proof: [{ ...proof, proofValue: multibaseBase58Encode(flipped) }],
      };
      expect(() => verifyEntryProof(tampered, allowed)).toThrow(INVALID_DID);
    }
  });

  it.each([
    ['type', 'Ed25519Signature2020'],
    ['cryptosuite', 'eddsa-rdfc-2022'],
    ['proofPurpose', 'authentication'],
    ['verificationMethod', `did:key:${multikey}#other`],
  ])('proof.%s の改変は拒否される', (member, value) => {
    const tampered = { ...entry, proof: [{ ...proof, [member]: value }] };
    expect(() => verifyEntryProof(tampered, allowed)).toThrow(INVALID_DID);
  });

  it('署名対象の本文（versionId・versionTime・state）の 1 文字の改変は拒否される', () => {
    const lastChar = entry.versionId.slice(-1);
    for (const patch of [
      { versionId: `${entry.versionId.slice(0, -1)}${lastChar === 'A' ? 'B' : 'A'}` },
      {
        versionTime: `${entry.versionTime.slice(0, 3)}${(Number(entry.versionTime[3]) + 1) % 10}${entry.versionTime.slice(4)}`,
      },
      { state: { ...entry.state, alsoKnownAs: ['x'] } },
    ]) {
      const tampered = { ...entry, ...patch } as WebVhLogEntry;
      expect(tampered).not.toEqual(entry);
      expect(() => verifyEntryProof(tampered, allowed)).toThrow(INVALID_DID);
    }
  });
});

describe('公式ベクタ: 正のベクタは、署名し直さずそのまま解決でき、解決結果が一致する（challenge を要求しない）', () => {
  it.each(
    POSITIVE.map((c) => [`${c.scenario}/${c.implementation}`, c] as const),
  )('%s', async (_name, c) => {
    const entries = parseDidLog(c.logText);
    const expected = c.expected as NonNullable<VectorCase['expected']>;
    // 失効した DID は DID Document を返さない（仕様: Deactivate。SDK は拒否する）。公式の ts 実装は `didDocument: null`、
    // 他の実装は文書を返して `deactivated: true` を添える。いずれも「失効」の期待値なので、SDK は拒否することを確かめる。
    // 失効の詳細（過去版の解決でメタデータに `deactivated: true`）は `v1/parameters.test.ts` が担う。
    if (expected.didDocumentMetadata.deactivated === true) {
      await expect(resolve(c, entries, didsOf(entries)[0] as string)).rejects.toThrow(INVALID_DID);
      // 失効行そのものの拒否が、チェーン・署名の不備によるものでないことを、失効の直前の版が解決できることで確かめる。
      const previous = entries[entries.length - 2] as WebVhLogEntry;
      const { document } = await resolveWithWitnessFile(previous.state.id, entries, c.witnessText, {
        versionId: previous.versionId,
      }).result;
      expect(document.id).toBe(previous.state.id);
      return;
    }
    const expectedDocument = expected.didDocument as NonNullable<typeof expected.didDocument>;
    const { document, metadata } = await resolve(c, entries, expectedDocument.id);

    // 解決側が補う暗黙のサービスを除いて、DID Document が一致する。
    const services = (expectedDocument.service as { id: string }[] | undefined)?.filter(
      (service) =>
        !IMPLICIT_SERVICE.test(service.id) || document.service?.some((s) => s.id === service.id),
    );
    const normalized = {
      ...expectedDocument,
      ...(services === undefined ? {} : { service: services }),
    };
    if (normalized.service?.length === 0) {
      delete (normalized as { service?: unknown }).service;
    }
    expect(JSON.parse(JSON.stringify(document))).toEqual(normalized);
    // Rust 実装の出力は watchers が無いとき `null`、Java は `deactivated` を省略する（仕様の既定値は `[]` / `false`）。
    const subset = (record: Record<string, unknown>) =>
      Object.fromEntries(
        COMPARED_METADATA.map((key) => [
          key,
          key === 'watchers'
            ? (record[key] ?? [])
            : key === 'deactivated'
              ? (record[key] ?? false)
              : record[key],
        ]),
      );
    expect(subset(metadata as unknown as Record<string, unknown>)).toEqual(
      subset(expected.didDocumentMetadata),
    );
  });
});

describe('公式ベクタ: 負のベクタは、拒否される', () => {
  it.each(
    NEGATIVE.map((c) => [`${c.scenario}/${c.implementation}`, c] as const),
  )('%s', async (_name, c) => {
    const entries = parseDidLog(c.logText);
    for (const did of didsOf(entries)) {
      await expect(resolve(c, entries, did)).rejects.toThrow(INVALID_DID);
    }
    // 公式の期待値は拒否（`invalidDid` / `invalidProof` / `invalidParameters`）。SDK はこれらを全て 2001 にまとめる。
    expect(c.expected?.didResolutionMetadata?.error).toMatch(/^invalid/);
  });

  it.each(
    didOnlyVectors().flatMap(({ scenario, dids }) =>
      dids.map((did) => [`${scenario}: ${did}`, did] as const),
    ),
  )('%s: DID の文字列だけで拒否され、取得を始めない', async (_name, did) => {
    let fetched = 0;
    globalThis.fetch = (async () => {
      fetched += 1;
      return new Response('', { status: 404 });
    }) as unknown as typeof fetch;
    await expect(resolveDidWebVhWithMetadata(did)).rejects.toThrow(INVALID_DID);
    expect(fetched).toBe(0);
  });
});
