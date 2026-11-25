/**
 * did:webvh のライフサイクル操作の `Object.prototype` 汚染耐性テスト
 *
 * `updateKeys` / `nextKeyHashes` / `document` / `deactivated` / `versionTime` を
 * プロトタイプ鎖で読むと、これらを**省略した**正当な生成・更新でも汚染値が採用される。
 * `updateKeys` は DID の**更新権限鍵集合**であり、汚染値が採用されると DID の更新権限が
 * 攻撃者の鍵へ差し替わったうえで `versionId`（前版とのハッシュチェーン）に焼き付き、
 * 署名済みの DID ログに残る。
 *
 * 更新時に `updateKeys` を省略する意味は「前版の鍵集合を引き継ぐ」であり、汚染下でも
 * 前版の鍵が引き継がれることを期待値とする。
 */

import { describe, expect, it } from 'bun:test';
import {
  withPollutedPrototype,
  withPollutedPrototypeAccessor,
} from '../../../../__tests__/prototype-pollution.fixtures.js';
import {
  createDidWebVh,
  updateDidWebVh,
  updateKeyHash,
  type WebVhUpdateOptions,
} from '../../method-webvh.js';
import { generateKey, signEntry } from '../webvh-fixtures.js';

const ATTACKER_KEY = 'z6MkAttackerUpdateKeyForPrototypePollutionTest';

/** 攻撃者が用意した偽の前版 Log（本物の Log とは無関係）。 */
const FORGED_PREVIOUS_LOG = [
  {
    versionId: '1-zForged',
    versionTime: '2020-01-01T00:00:00.000Z',
    parameters: { updateKeys: [ATTACKER_KEY] },
    state: {
      '@context': ['https://www.w3.org/ns/did/v1'],
      id: 'did:webvh:zForgedScid:attacker.example',
      verificationMethod: [],
      authentication: [],
      assertionMethod: [],
    },
  },
];

describe('did:webvh ライフサイクルの Object.prototype 汚染耐性', () => {
  it('継承した nextKeyHashes は初版の事前コミットに載らない', () => {
    const key1 = generateKey();
    const { logEntry } = withPollutedPrototype(
      { nextKeyHashes: [updateKeyHash(ATTACKER_KEY)] },
      () => createDidWebVh({ domain: 'vericerts.io', updateKeys: [key1.multikey] }),
    );
    expect(logEntry.parameters.nextKeyHashes).toBeUndefined();
  });

  it('継承した document は初版 state に載らない', () => {
    const key1 = generateKey();
    const { logEntry } = withPollutedPrototype(
      { document: { '@context': ['https://attacker.example/v1'], verificationMethod: [] } },
      () => createDidWebVh({ domain: 'vericerts.io', updateKeys: [key1.multikey] }),
    );
    expect(logEntry.state['@context']).not.toContain('https://attacker.example/v1');
  });

  it('更新時に継承した updateKeys は前版の鍵集合を差し替えない', () => {
    const key1 = generateKey();
    const { did, logEntry: genesis } = createDidWebVh({
      domain: 'vericerts.io',
      updateKeys: [key1.multikey],
    });
    const signedGenesis = signEntry(genesis, key1);

    const v2 = withPollutedPrototype({ updateKeys: [ATTACKER_KEY] }, () =>
      updateDidWebVh({
        previousLog: [signedGenesis],
        state: {
          '@context': ['https://www.w3.org/ns/did/v1'],
          id: did,
          verificationMethod: [],
          authentication: [],
          assertionMethod: [],
        },
        // updateKeys は渡していない ＝ 前版を引き継ぐ意図。
      }),
    );
    expect(v2.parameters.updateKeys).toEqual([key1.multikey]);
    expect(v2.parameters.updateKeys).not.toContain(ATTACKER_KEY);
  });

  it('更新時に継承した nextKeyHashes は次版の事前コミットに載らない', () => {
    const key1 = generateKey();
    const { did, logEntry: genesis } = createDidWebVh({
      domain: 'vericerts.io',
      updateKeys: [key1.multikey],
    });
    const signedGenesis = signEntry(genesis, key1);

    const v2 = withPollutedPrototype({ nextKeyHashes: [updateKeyHash(ATTACKER_KEY)] }, () =>
      updateDidWebVh({
        previousLog: [signedGenesis],
        state: {
          '@context': ['https://www.w3.org/ns/did/v1'],
          id: did,
          verificationMethod: [],
          authentication: [],
          assertionMethod: [],
        },
      }),
    );
    expect(v2.parameters.nextKeyHashes).toBeUndefined();
  });

  it('明示的に渡した updateKeys / nextKeyHashes は従来どおり反映される（正常系）', () => {
    const key1 = generateKey();
    const key2 = generateKey();
    const { did, logEntry: genesis } = createDidWebVh({
      domain: 'vericerts.io',
      updateKeys: [key1.multikey],
      nextKeyHashes: [updateKeyHash(key2.multikey)],
    });
    expect(genesis.parameters.nextKeyHashes).toEqual([updateKeyHash(key2.multikey)]);

    const v2 = updateDidWebVh({
      previousLog: [signEntry(genesis, key1)],
      state: {
        '@context': ['https://www.w3.org/ns/did/v1'],
        id: did,
        verificationMethod: [],
        authentication: [],
        assertionMethod: [],
      },
      updateKeys: [key2.multikey],
      nextKeyHashes: [],
    });
    expect(v2.parameters.updateKeys).toEqual([key2.multikey]);
    expect(v2.parameters.nextKeyHashes).toEqual([]);
  });

  it('previousLog を省略した呼び出しは継承した偽 Log（データ汚染）を前版として受理しない', () => {
    const state = {
      '@context': ['https://www.w3.org/ns/did/v1'],
      id: 'did:webvh:zForgedScid:attacker.example',
      verificationMethod: [],
      authentication: [],
      assertionMethod: [],
    };

    expect(() =>
      withPollutedPrototype({ previousLog: FORGED_PREVIOUS_LOG }, () =>
        updateDidWebVh({ state } as unknown as WebVhUpdateOptions),
      ),
    ).toThrow();
  });

  it('previousLog を省略した呼び出しは継承した偽 Log（アクセサ汚染）を前版として受理しない', () => {
    const state = {
      '@context': ['https://www.w3.org/ns/did/v1'],
      id: 'did:webvh:zForgedScid:attacker.example',
      verificationMethod: [],
      authentication: [],
      assertionMethod: [],
    };

    expect(() =>
      withPollutedPrototypeAccessor({ previousLog: () => FORGED_PREVIOUS_LOG }, () =>
        updateDidWebVh({ state } as unknown as WebVhUpdateOptions),
      ),
    ).toThrow();
  });
});
