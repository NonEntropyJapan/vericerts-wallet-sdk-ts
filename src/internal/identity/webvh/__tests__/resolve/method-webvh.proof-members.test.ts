/**
 * did:webvh の proof のメンバ（DIF didwebvh specification.md「Authorized Keys」）。
 *
 * 仕様が proof に要求するのは `type` / `cryptosuite` / `proofPurpose` / `verificationMethod` だけで、`challenge` は要求しない
 * （旧 SDK の `proof.challenge === versionId` の検査は外した。ログ位置は `versionId` を含む署名対象が束縛する。
 * `./method-webvh.log-position.test.ts`）。proof に余分な `challenge` があっても `proofConfig` の 1 メンバとして署名され、検証できる。
 */

import { afterEach, describe, expect, it } from 'bun:test';
import { updateKeysOf, type WebVhLogEntry, type WebVhProof } from '../../codec.js';
import { createDidWebVh, resolveDidWebVh } from '../../method-webvh.js';
import { verifyEntryProof } from '../../proof.js';
import { generateKey, mockFetchOnce, restoreFetch, signEntry, toJsonl } from '../webvh-fixtures.js';
import { buildRotatedV2, INVALID_DID, signWithConfig } from './log-position-fixtures.js';

afterEach(() => {
  restoreFetch();
});

describe('did:webvh proof のメンバ（challenge を要求しない）', () => {
  // challenge の扱い: `challenge` は仕様の要件にない。あっても proofConfig の 1 メンバとして署名され、検証できる。
  it('proof に余分な challenge メンバがあっても（値が何であっても）署名が正しければ検証でき、解決できる', async () => {
    const key = generateKey();
    const { did, logEntry } = createDidWebVh({
      domain: 'vericerts.io',
      updateKeys: [key.multikey],
    });
    const genesis = signWithConfig(logEntry, key, { challenge: logEntry.versionId });
    const draft = buildRotatedV2(did, signEntry(logEntry, key), key);
    const v2 = signWithConfig({ ...draft, proof: undefined } as WebVhLogEntry, key, {
      challenge: '2-zUnrelatedValue',
    });

    expect(() => verifyEntryProof(genesis, updateKeysOf(genesis))).not.toThrow();
    mockFetchOnce(toJsonl([genesis, v2]));
    expect((await resolveDidWebVh(did)).id).toBe(did);
    // challenge は他のメンバと同じく署名対象: 署名後に書き換えれば（または消せば）署名が合わない。
    const proof = (genesis.proof as readonly WebVhProof[])[0] as WebVhProof;
    for (const tampered of [
      { ...proof, challenge: 'other' },
      { ...proof, challenge: undefined },
    ]) {
      const entry = { ...genesis, proof: [tampered] } as WebVhLogEntry;
      expect(() => verifyEntryProof(entry, updateKeysOf(entry))).toThrow(INVALID_DID);
    }
  });

  it('challenge の無い proof（公式ベクタと同じ形）は、正規に署名されていれば検証できる', () => {
    const key = generateKey();
    const { logEntry } = createDidWebVh({ domain: 'vericerts.io', updateKeys: [key.multikey] });
    const entry = signWithConfig(logEntry, key, {});

    expect(entry.proof?.[0]).not.toHaveProperty('challenge');
    expect(() => verifyEntryProof(entry, updateKeysOf(entry))).not.toThrow();
  });

  // proof の必須要素の改変
  it('proofPurpose が assertionMethod 以外、cryptosuite / type 不一致の proof は拒否される', () => {
    const key = generateKey();
    const { logEntry } = createDidWebVh({ domain: 'vericerts.io', updateKeys: [key.multikey] });
    const variants: Record<string, unknown>[] = [
      { proofPurpose: 'authentication' },
      { cryptosuite: 'eddsa-rdfc-2022' },
      { type: 'Ed25519Signature2020' },
      { verificationMethod: `did:key:${key.multikey}#other` },
    ];
    for (const config of variants) {
      const entry = signWithConfig(logEntry, key, config);
      expect(() => verifyEntryProof(entry, updateKeysOf(entry))).toThrow(INVALID_DID);
    }
    const ok = signWithConfig(logEntry, key, {});
    expect(() => verifyEntryProof(ok, updateKeysOf(ok))).not.toThrow();
  });
});
