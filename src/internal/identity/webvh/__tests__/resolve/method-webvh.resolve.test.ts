/**
 * MethodWebVh.resolve / resolveDidWebVh の DID Log 検証テスト。
 *
 * 実 Ed25519 署名で構築した DID Log を `globalThis.fetch` モック経由で解決し、
 * 正常チェーン / 改竄検知 / deactivated / scid 不一致 / 取得失敗を検証する。
 */

import { afterEach, describe, expect, it } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../../../errors.js';
import type { DIDDocument } from '../../../did.js';
import {
  createDidWebVh,
  MethodWebVh,
  resolveDidWebVh,
  updateDidWebVh,
} from '../../method-webvh.js';
import {
  generateKey,
  mockFetchOnce,
  mockFetchReject,
  restoreFetch,
  signEntry,
  type TestKey,
  toJsonl,
} from '../webvh-fixtures.js';

const INVALID_DID = new VericertsError(ErrorCodes.INVALID_DID);
const DID_NOT_FOUND = new VericertsError(ErrorCodes.DID_NOT_FOUND);

afterEach(() => {
  restoreFetch();
});

/** 単一版（初版のみ）の署名済み DID Log を作る。 */
function buildGenesisLog(key: TestKey): { did: string; jsonl: string } {
  const { did, logEntry } = createDidWebVh({
    domain: 'vericerts.io',
    updateKeys: [key.multikey],
    document: {
      '@context': ['https://www.w3.org/ns/did/v1'],
      verificationMethod: [],
      authentication: [],
      assertionMethod: [],
    },
  });
  const signed = signEntry(logEntry, key);
  return { did, jsonl: toJsonl([signed]) };
}

describe('resolveDidWebVh 正常系', () => {
  it('初版のみの DID Log を検証して state を返す', async () => {
    const key = generateKey();
    const { did, jsonl } = buildGenesisLog(key);
    mockFetchOnce(jsonl);

    const doc = await resolveDidWebVh(did);
    expect(doc.id).toBe(did);
  });

  it('正規の鍵ローテーション 2 版チェーンを検証する', async () => {
    const key1 = generateKey();
    const key2 = generateKey();
    const { did, logEntry: genesis } = createDidWebVh({
      domain: 'vericerts.io',
      updateKeys: [key1.multikey],
    });
    const signedGenesis = signEntry(genesis, key1);

    const newState: DIDDocument = {
      '@context': ['https://www.w3.org/ns/did/v1'],
      id: did,
      verificationMethod: [],
      authentication: [],
      assertionMethod: [],
    };
    const v2 = updateDidWebVh({
      previousLog: [signedGenesis],
      state: newState,
      updateKeys: [key2.multikey],
    });
    // 2 版目の proof は「前版で有効な updateKeys」= key1 で署名する。
    const signedV2 = signEntry(v2, key1);
    mockFetchOnce(toJsonl([signedGenesis, signedV2]));

    const doc = await resolveDidWebVh(did);
    expect(doc.id).toBe(did);
    expect(doc.verificationMethod).toEqual([]);
  });

  it('versionId 指定で過去版を返す', async () => {
    const key = generateKey();
    const { did, logEntry: genesis } = createDidWebVh({
      domain: 'vericerts.io',
      updateKeys: [key.multikey],
    });
    const signedGenesis = signEntry(genesis, key);
    const v2 = updateDidWebVh({
      previousLog: [signedGenesis],
      state: {
        '@context': ['https://www.w3.org/ns/did/v1'],
        id: did,
        verificationMethod: [],
        authentication: [],
        assertionMethod: [],
      },
    });
    const signedV2 = signEntry(v2, key);
    mockFetchOnce(toJsonl([signedGenesis, signedV2]));

    const doc = await resolveDidWebVh(did, { versionId: signedGenesis.versionId });
    expect(doc.id).toBe(did);
  });

  it('MethodWebVh.resolve でも解決できる', async () => {
    const key = generateKey();
    const { did, jsonl } = buildGenesisLog(key);
    mockFetchOnce(jsonl);

    const doc = await new MethodWebVh().resolve(did);
    expect(doc.id).toBe(did);
  });
});

describe('resolveDidWebVh 改竄検知', () => {
  it('state を改竄すると scid 検証で INVALID_DID', async () => {
    const key = generateKey();
    const { did, logEntry } = createDidWebVh({
      domain: 'vericerts.io',
      updateKeys: [key.multikey],
    });
    const signed = signEntry(logEntry, key);
    // state.controller を後付けで改竄する（scid の self-certifying と不整合になる）。
    const tampered = {
      ...signed,
      state: { ...signed.state, controller: 'did:webvh:zEvil:vericerts.io' },
    };
    mockFetchOnce(toJsonl([tampered]));

    await expect(resolveDidWebVh(did)).rejects.toThrow(INVALID_DID);
  });

  it('proof 署名を改竄すると INVALID_DID', async () => {
    const key = generateKey();
    const { did, logEntry } = createDidWebVh({
      domain: 'vericerts.io',
      updateKeys: [key.multikey],
    });
    const signed = signEntry(logEntry, key);
    const firstProof = signed.proof?.[0];
    if (firstProof === undefined) {
      throw new Error('proof missing');
    }
    // proofValue を別の有効 base58 文字列に差し替える。
    const tampered = {
      ...signed,
      proof: [
        {
          ...firstProof,
          proofValue: 'z111111111111111111111111111111111111111111111111111111111111111111',
        },
      ],
    };
    mockFetchOnce(toJsonl([tampered]));

    await expect(resolveDidWebVh(did)).rejects.toThrow(INVALID_DID);
  });

  it('2 版目を許可されていない鍵で署名すると INVALID_DID', async () => {
    const key1 = generateKey();
    const rogue = generateKey();
    const { did, logEntry: genesis } = createDidWebVh({
      domain: 'vericerts.io',
      updateKeys: [key1.multikey],
    });
    const signedGenesis = signEntry(genesis, key1);
    const v2 = updateDidWebVh({
      previousLog: [signedGenesis],
      state: {
        '@context': ['https://www.w3.org/ns/did/v1'],
        id: did,
        verificationMethod: [],
        authentication: [],
        assertionMethod: [],
      },
    });
    // rogue 鍵は updateKeys に無いため検証失敗するはず。
    const signedV2 = signEntry(v2, rogue);
    mockFetchOnce(toJsonl([signedGenesis, signedV2]));

    await expect(resolveDidWebVh(did)).rejects.toThrow(INVALID_DID);
  });

  it('2 版目の versionId を改竄するとチェーン検証で INVALID_DID', async () => {
    const key = generateKey();
    const { did, logEntry: genesis } = createDidWebVh({
      domain: 'vericerts.io',
      updateKeys: [key.multikey],
    });
    const signedGenesis = signEntry(genesis, key);
    const v2 = updateDidWebVh({
      previousLog: [signedGenesis],
      state: {
        '@context': ['https://www.w3.org/ns/did/v1'],
        id: did,
        verificationMethod: [],
        authentication: [],
        assertionMethod: [],
      },
    });
    const signedV2 = signEntry(v2, key);
    const tampered = { ...signedV2, versionId: `2-Qm${'W'.repeat(44)}` };
    mockFetchOnce(toJsonl([signedGenesis, tampered]));

    await expect(resolveDidWebVh(did)).rejects.toThrow(INVALID_DID);
  });
});

describe('resolveDidWebVh deactivated', () => {
  it('parameters.deactivated:true の最新版は失効扱い（INVALID_DID）', async () => {
    const key = generateKey();
    const { did, logEntry: genesis } = createDidWebVh({
      domain: 'vericerts.io',
      updateKeys: [key.multikey],
    });
    const signedGenesis = signEntry(genesis, key);
    const v2 = updateDidWebVh({
      previousLog: [signedGenesis],
      state: {
        '@context': ['https://www.w3.org/ns/did/v1'],
        id: did,
        verificationMethod: [],
        authentication: [],
        assertionMethod: [],
      },
      deactivated: true,
    });
    const signedV2 = signEntry(v2, key);
    mockFetchOnce(toJsonl([signedGenesis, signedV2]));

    await expect(resolveDidWebVh(did)).rejects.toThrow(INVALID_DID);
  });
});

describe('resolveDidWebVh scid 不一致', () => {
  it('DID の scid が Log の初版 scid と異なると INVALID_DID', async () => {
    const key = generateKey();
    const { jsonl } = buildGenesisLog(key);
    // DID 文字列の scid を別物に差し替える（Log は正規のまま）。
    const wrongDid = `did:webvh:Qm${'B'.repeat(44)}:vericerts.io`;
    mockFetchOnce(jsonl);

    await expect(resolveDidWebVh(wrongDid)).rejects.toThrow(INVALID_DID);
  });
});

describe('resolveDidWebVh 取得失敗', () => {
  it('ネットワークエラーは DID_NOT_FOUND（2003）', async () => {
    const key = generateKey();
    const { did } = buildGenesisLog(key);
    mockFetchReject();
    await expect(resolveDidWebVh(did)).rejects.toThrow(DID_NOT_FOUND);
  });

  it('HTTP 404 は DID_NOT_FOUND（2003）', async () => {
    const key = generateKey();
    const { did, jsonl } = buildGenesisLog(key);
    mockFetchOnce(jsonl, { status: 404 });
    await expect(resolveDidWebVh(did)).rejects.toThrow(DID_NOT_FOUND);
  });

  it('非 HTTPS リダイレクトは DID_NOT_FOUND（2003）', async () => {
    const key = generateKey();
    const { did, jsonl } = buildGenesisLog(key);
    mockFetchOnce(jsonl, { url: 'http://evil.example/.well-known/did.jsonl' });
    await expect(resolveDidWebVh(did)).rejects.toThrow(DID_NOT_FOUND);
  });
});
