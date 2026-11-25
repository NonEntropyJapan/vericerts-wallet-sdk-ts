/**
 * `parameters` の検証・既定値・`null` の読み替え・失効・ttl・portable（did:webvh v1.0、spec: `did:webvh` DID Method
 * Parameters）。解決メタデータの内容も確かめる（spec: Read (Resolve) の DID Document Metadata）。
 */

import { afterEach, describe, expect, it } from 'bun:test';
import { forgeGenesis, generateKey, restoreFetch, signEntry } from '../webvh-fixtures.js';
import {
  appendSigned,
  forgeNext,
  INVALID_DID,
  resolveLog,
  signedGenesis,
  stateOf,
} from './log-builders.js';

afterEach(() => {
  restoreFetch();
});

describe('既定値とメタデータ', () => {
  it('初版で省略したパラメータは既定値になり、メタデータは仕様どおりの形（ttl・threshold は文字列）で返る', async () => {
    const { did, genesis } = signedGenesis();
    const { metadata } = await resolveLog(did, [genesis]);
    expect(metadata).toEqual({
      versionId: genesis.versionId,
      versionTime: genesis.versionTime,
      created: genesis.versionTime,
      updated: genesis.versionTime,
      scid: genesis.parameters.scid as string,
      portable: false,
      deactivated: false,
      ttl: '3600',
      witness: {},
      watchers: [],
    });
  });

  it('ttl・watchers を宣言すると、メタデータに反映され、省略した後続の版でも維持される', async () => {
    const { key, did, genesis } = signedGenesis({
      ttl: 60,
      watchers: ['https://watcher.example.com/'],
    });
    const v2 = appendSigned([genesis], key);
    const { metadata } = await resolveLog(did, [genesis, v2]);
    expect(metadata.ttl).toBe('60');
    expect(metadata.watchers).toEqual(['https://watcher.example.com/']);
    expect(metadata.created).toBe(genesis.versionTime);
    expect(metadata.updated).toBe(v2.versionTime);
  });

  it('後続の版で watchers を `[]` にすると解除される。ttl は更新できる', async () => {
    const { key, did, genesis } = signedGenesis({ watchers: ['https://watcher.example.com/'] });
    const v2 = appendSigned([genesis], key, { watchers: [], ttl: 0 });
    const { metadata } = await resolveLog(did, [genesis, v2]);
    expect(metadata.watchers).toEqual([]);
    expect(metadata.ttl).toBe('0');
  });
});

describe('パラメータの値の検証', () => {
  const cases: [string, Record<string, unknown>][] = [
    ['未知のパラメータ名（prerotation は 0.5 で廃止）', { prerotation: true }],
    ['未知のパラメータ名', { custom: 1 }],
    ['ttl が負', { ttl: -1 }],
    ['ttl が 2^31 超', { ttl: 2 ** 31 + 1 }],
    ['ttl が整数でない', { ttl: 1.5 }],
    ['ttl が文字列', { ttl: '3600' }],
    ['portable が真偽値でない', { portable: 'true' }],
    ['deactivated が真偽値でない', { deactivated: 1 }],
    ['watchers が配列でない', { watchers: 'https://watcher.example.com/' }],
    ['watchers に URL でない要素', { watchers: ['not a url'] }],
    ['watchers に http(s) 以外', { watchers: ['ftp://watcher.example.com/'] }],
    ['watchers が重複', { watchers: ['https://w.example.com/', 'https://w.example.com/'] }],
    ['updateKeys が配列でない', { updateKeys: 'z6Mk' }],
    ['nextKeyHashes に文字列でない要素', { nextKeyHashes: [1] }],
    ['witness が配列', { witness: [] }],
  ];
  it.each(cases)('初版: %s は拒否される', async (_label, parameters) => {
    const key = generateKey();
    const { did, entry } = forgeGenesis({ key, parameters });
    await expect(resolveLog(did, [signEntry(entry, key)])).rejects.toThrow(INVALID_DID);
  });

  it('後続の版に scid を書くと拒否される', async () => {
    const { key, did, genesis } = signedGenesis();
    const v2 = signEntry(
      forgeNext(genesis, stateOf(did), {
        updateKeys: [key.multikey],
        scid: genesis.parameters.scid as string,
      }),
      key,
    );
    await expect(resolveLog(did, [genesis, v2])).rejects.toThrow(INVALID_DID);
  });
});

describe('null の読み替え（古いログの null は既定値として受け付ける。spec の SHOULD）', () => {
  it('初版・後続の版の null は、各パラメータの既定値（解除）として扱われる', async () => {
    const key = generateKey();
    const { did, entry } = forgeGenesis({
      key,
      parameters: {
        watchers: null,
        witness: null,
        nextKeyHashes: null,
        ttl: null,
        portable: null,
        deactivated: null,
      },
    });
    const genesis = signEntry(entry, key);
    const v2 = signEntry(
      forgeNext(genesis, stateOf(did), {
        updateKeys: [key.multikey],
        watchers: null,
        witness: null,
        ttl: null,
      } as never),
      key,
    );
    const { metadata } = await resolveLog(did, [genesis, v2]);
    expect(metadata).toMatchObject({
      portable: false,
      deactivated: false,
      ttl: '3600',
      witness: {},
      watchers: [],
    });
  });

  it('updateKeys: null の初版は拒否される（更新鍵には既定値がない）', async () => {
    const key = generateKey();
    const { did, entry } = forgeGenesis({ key, parameters: { updateKeys: null } });
    await expect(resolveLog(did, [signEntry(entry, key)])).rejects.toThrow(INVALID_DID);
  });
});

describe('失効（parameters.deactivated）', () => {
  it('parameters.deactivated: true の最新版は解決できない。失効前の版を指定すれば返り、メタデータは deactivated: true', async () => {
    const { key, did, genesis } = signedGenesis();
    const v2 = appendSigned([genesis], key, { deactivated: true });
    await expect(resolveLog(did, [genesis, v2])).rejects.toThrow(INVALID_DID);
    const { document, metadata } = await resolveLog(did, [genesis, v2], {
      versionId: genesis.versionId,
    });
    expect(document.id).toBe(did);
    expect(metadata.deactivated).toBe(true);
    expect(metadata.versionId).toBe(genesis.versionId);
  });

  it('失効の置き場所は parameters であり、state.deactivated は失効を表さない（ビルダーは混同を拒否する）', async () => {
    const { key, did, genesis } = signedGenesis();
    // 旧 SDK の表記。state の未知メンバとして残るだけで、DID を失効させない。
    const v2 = signEntry(
      forgeNext(genesis, stateOf(did, { deactivated: true }), { updateKeys: [key.multikey] }),
      key,
    );
    const { metadata } = await resolveLog(did, [genesis, v2]);
    expect(metadata.deactivated).toBe(false);
    expect(() =>
      appendSigned([genesis], key, { state: stateOf(did, { deactivated: true }) }),
    ).toThrow(INVALID_DID);
  });

  it('失効の取り消し（deactivated: false への再有効化）と失効後の追記は拒否される', async () => {
    const { key, did, genesis } = signedGenesis();
    const v2 = appendSigned([genesis], key, { deactivated: true });
    const revive = signEntry(
      forgeNext(v2, stateOf(did), { updateKeys: [key.multikey], deactivated: false }),
      key,
    );
    await expect(resolveLog(did, [genesis, v2, revive], { versionNumber: 2 })).rejects.toThrow(
      INVALID_DID,
    );
    expect(() => appendSigned([genesis, v2], key)).toThrow(INVALID_DID);
  });

  it('updateKeys を `[]` にして失効する版は受理される（仕様の SHOULD）。以降は署名できる鍵がない', async () => {
    const { key, did, genesis } = signedGenesis();
    const v2 = appendSigned([genesis], key, { deactivated: true, updateKeys: [] });
    const { metadata } = await resolveLog(did, [genesis, v2], { versionId: genesis.versionId });
    expect(metadata.deactivated).toBe(true);
  });
});

describe('ビルダーの検査', () => {
  it('portable: true は初版でだけ指定でき、後続の更新では拒否される', () => {
    const { key, genesis } = signedGenesis({ portable: true });
    expect(genesis.parameters.portable).toBe(true);
    expect(() => appendSigned([genesis], key, { portable: true })).toThrow(INVALID_DID);
    const plain = signedGenesis();
    expect(() => appendSigned([plain.genesis], plain.key, { portable: true })).toThrow(INVALID_DID);
  });

  it('値域外の ttl・watchers・witness は生成・更新の時点で拒否される', () => {
    const key = generateKey();
    expect(() => signedGenesis({ updateKeys: [key.multikey], ttl: -1 })).toThrow(INVALID_DID);
    expect(() => signedGenesis({ watchers: ['nope'] })).toThrow(INVALID_DID);
    expect(() => signedGenesis({ portable: 'yes' as never })).toThrow(INVALID_DID);
    const { key: k2, genesis } = signedGenesis();
    expect(() => appendSigned([genesis], k2, { ttl: 2 ** 31 + 1 })).toThrow(INVALID_DID);
  });
});
