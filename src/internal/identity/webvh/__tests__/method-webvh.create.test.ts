/**
 * createDidWebVh / updateDidWebVh と MethodWebVh の DIDMethod インターフェース挙動のテスト。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import type { DIDDocument } from '../../did.js';
import { versionNumberOf } from '../codec.js';
import { createDidWebVh, MethodWebVh, updateDidWebVh } from '../method-webvh.js';
import { generateKey, signEntry } from './webvh-fixtures.js';

const INVALID_DID = new VericertsError(ErrorCodes.INVALID_DID);
const METHOD_NOT_SUPPORTED = new VericertsError(ErrorCodes.METHOD_NOT_SUPPORTED);

describe('createDidWebVh', () => {
  it('did:webvh:{scid}:{domain} 形式の DID を生成する', () => {
    const key = generateKey();
    const { did, logEntry } = createDidWebVh({
      domain: 'vericerts.io',
      updateKeys: [key.multikey],
    });
    expect(did.startsWith('did:webvh:')).toBe(true);
    expect(did.endsWith(':vericerts.io')).toBe(true);
    expect(logEntry.state.id).toBe(did);
    expect(versionNumberOf(logEntry.versionId)).toBe(1);
    // 初版の versionId は `1-<entryHash>`（SCID とは別の値。SCID は parameters.scid と DID に入る）。
    const scid = did.slice('did:webvh:'.length, did.lastIndexOf(':vericerts.io'));
    expect(logEntry.parameters.scid).toBe(scid);
    expect(logEntry.versionId).toMatch(/^1-Qm[1-9A-HJ-NP-Za-km-z]{44}$/);
    expect(logEntry.versionId).not.toBe(`1-${scid}`);
  });

  it('genesis の parameters.method は did:webvh:1.0', () => {
    const key = generateKey();
    const { logEntry } = createDidWebVh({
      domain: 'vericerts.io',
      updateKeys: [key.multikey],
    });
    expect(logEntry.parameters.method).toBe('did:webvh:1.0');
  });

  it('path 付き DID を生成する', () => {
    const key = generateKey();
    const { did } = createDidWebVh({
      domain: 'vericerts.io',
      path: 'users:alice',
      updateKeys: [key.multikey],
    });
    expect(did.endsWith(':vericerts.io:users:alice')).toBe(true);
  });

  it('同一入力で決定論的に同じ scid を生成する', () => {
    const key = generateKey();
    const opts = {
      domain: 'vericerts.io',
      updateKeys: [key.multikey],
      versionTime: '2026-04-01T00:00:00Z',
    };
    const a = createDidWebVh(opts);
    const b = createDidWebVh(opts);
    expect(a.did).toBe(b.did);
  });

  it('domain 空は INVALID_DID', () => {
    const key = generateKey();
    expect(() => createDidWebVh({ domain: '', updateKeys: [key.multikey] })).toThrow(INVALID_DID);
  });

  it('updateKeys 空は INVALID_DID', () => {
    expect(() => createDidWebVh({ domain: 'vericerts.io', updateKeys: [] })).toThrow(INVALID_DID);
  });
});

describe('updateDidWebVh', () => {
  it('前版 versionId を含むハッシュチェーンで次版 versionId を生成する', () => {
    const key = generateKey();
    const { did, logEntry: genesis } = createDidWebVh({
      domain: 'vericerts.io',
      updateKeys: [key.multikey],
    });
    const signedGenesis = signEntry(genesis, key);
    const newState: DIDDocument = {
      '@context': ['https://www.w3.org/ns/did/v1'],
      id: did,
      verificationMethod: [],
      authentication: [],
      assertionMethod: [],
    };
    const v2 = updateDidWebVh({ previousLog: [signedGenesis], state: newState });
    expect(versionNumberOf(v2.versionId)).toBe(2);
    expect(v2.state.id).toBe(did);
  });

  it('updateKeys 未指定なら前版を継続する', () => {
    const key = generateKey();
    const { did, logEntry: genesis } = createDidWebVh({
      domain: 'vericerts.io',
      updateKeys: [key.multikey],
    });
    const v2 = updateDidWebVh({
      previousLog: [signEntry(genesis, key)],
      state: {
        '@context': ['https://www.w3.org/ns/did/v1'],
        id: did,
        verificationMethod: [],
        authentication: [],
        assertionMethod: [],
      },
    });
    expect(v2.parameters.updateKeys).toEqual([key.multikey]);
  });

  it('previousLog 空は INVALID_DID', () => {
    expect(() =>
      updateDidWebVh({
        previousLog: [],
        state: {
          '@context': [],
          id: 'did:webvh:z:vericerts.io',
          verificationMethod: [],
          authentication: [],
          assertionMethod: [],
        },
      }),
    ).toThrow(INVALID_DID);
  });

  it('updateKeys 空配列は INVALID_DID（解決不能チェーン防止）', () => {
    const key = generateKey();
    const { did, logEntry: genesis } = createDidWebVh({
      domain: 'vericerts.io',
      updateKeys: [key.multikey],
    });
    expect(() =>
      updateDidWebVh({
        previousLog: [signEntry(genesis, key)],
        state: {
          '@context': ['https://www.w3.org/ns/did/v1'],
          id: did,
          verificationMethod: [],
          authentication: [],
          assertionMethod: [],
        },
        updateKeys: [],
      }),
    ).toThrow(INVALID_DID);
  });

  it('state.id が前版と異なると INVALID_DID', () => {
    const key = generateKey();
    const { logEntry: genesis } = createDidWebVh({
      domain: 'vericerts.io',
      updateKeys: [key.multikey],
    });
    expect(() =>
      updateDidWebVh({
        previousLog: [signEntry(genesis, key)],
        state: {
          '@context': [],
          id: 'did:webvh:zDifferent:vericerts.io',
          verificationMethod: [],
          authentication: [],
          assertionMethod: [],
        },
      }),
    ).toThrow(INVALID_DID);
  });
});

describe('MethodWebVh インターフェース', () => {
  it('method() は webvh', () => {
    expect(new MethodWebVh().method()).toBe('webvh');
  });

  it('create は METHOD_NOT_SUPPORTED', async () => {
    await expect(
      new MethodWebVh().create({ keyType: 'Ed25519', publicKey: new Uint8Array(32) }),
    ).rejects.toThrow(METHOD_NOT_SUPPORTED);
  });

  it('update は METHOD_NOT_SUPPORTED', async () => {
    await expect(new MethodWebVh().update('did:webvh:z:vericerts.io', {})).rejects.toThrow(
      METHOD_NOT_SUPPORTED,
    );
  });

  it('deactivate は METHOD_NOT_SUPPORTED', async () => {
    await expect(new MethodWebVh().deactivate('did:webvh:z:vericerts.io')).rejects.toThrow(
      METHOD_NOT_SUPPORTED,
    );
  });
});

describe('GDPR Art.9 特別カテゴリ属性ガード（10601）', () => {
  const SPECIAL_CATEGORY = new VericertsError(ErrorCodes.GDPR_SPECIAL_CATEGORY_ON_CHAIN);

  it('createDidWebVh は document に Art.9 属性を含むと 10601 を投げる', () => {
    const key = generateKey();
    expect(() =>
      createDidWebVh({
        domain: 'vericerts.io',
        updateKeys: [key.multikey],
        document: {
          '@context': ['https://www.w3.org/ns/did/v1'],
          verificationMethod: [],
          authentication: [],
          assertionMethod: [],
          service: [{ id: '#s1', type: 'Profile', serviceEndpoint: { religion: 'undisclosed' } }],
        },
      }),
    ).toThrow(SPECIAL_CATEGORY);
  });

  it('updateDidWebVh は次版 state に Art.9 属性を含むと 10601 を投げる', () => {
    const key = generateKey();
    const { did, logEntry: genesis } = createDidWebVh({
      domain: 'vericerts.io',
      updateKeys: [key.multikey],
    });
    const signedGenesis = signEntry(genesis, key);
    const tainted = {
      '@context': ['https://www.w3.org/ns/did/v1'],
      id: did,
      verificationMethod: [],
      authentication: [],
      assertionMethod: [],
      service: [{ id: '#s1', type: 'Profile', serviceEndpoint: { birth_date: '1990-01-01' } }],
    } as unknown as DIDDocument;
    expect(() => updateDidWebVh({ previousLog: [signedGenesis], state: tainted })).toThrow(
      SPECIAL_CATEGORY,
    );
  });

  it('送出されるのは 10601（レジストリのメッセージ変更に依存しない）', () => {
    const key = generateKey();
    try {
      createDidWebVh({
        domain: 'vericerts.io',
        updateKeys: [key.multikey],
        document: {
          '@context': ['https://www.w3.org/ns/did/v1'],
          verificationMethod: [],
          authentication: [],
          assertionMethod: [],
          service: [{ id: '#s1', type: 'Profile', serviceEndpoint: { health: 'x' } }],
        },
      });
      throw new Error('should have thrown');
    } catch (error) {
      expect(error).toBeInstanceOf(VericertsError);
      expect((error as VericertsError).code).toBe(ErrorCodes.GDPR_SPECIAL_CATEGORY_ON_CHAIN);
    }
  });

  it('Art.9 属性を含まない正規の DID Document は従来どおり生成できる', () => {
    const key = generateKey();
    expect(() =>
      createDidWebVh({
        domain: 'vericerts.io',
        updateKeys: [key.multikey],
        document: {
          '@context': ['https://www.w3.org/ns/did/v1'],
          verificationMethod: [],
          authentication: [],
          assertionMethod: [],
          service: [
            { id: '#s1', type: 'DIDCommMessaging', serviceEndpoint: 'https://vericerts.io' },
          ],
        },
      }),
    ).not.toThrow();
  });
});
