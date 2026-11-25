/**
 * `parameters.method` の検証（did:webvh v1.0、spec: `did:webvh` DID Method Parameters の `method`、
 * The DID Log File の「検証に失敗する例」6）。`did:webvh:1.0` 以外（`did:webvh:0.4` を含む）は拒否し、
 * 互換期間も移行ツールも設けない。未知の値を既定値や下位版へ落とさない。
 */

import { afterEach, describe, expect, it } from 'bun:test';
import { createDidWebVh } from '../../method-webvh.js';
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

describe('did:webvh:1.0 の生成と解決', () => {
  it('生成する初版の method は did:webvh:1.0 で、そのまま解決できる', async () => {
    const { did, genesis } = signedGenesis();
    expect(genesis.parameters.method).toBe('did:webvh:1.0');
    const { document } = await resolveLog(did, [genesis]);
    expect(document.id).toBe(did);
  });
});

describe('知らない method の拒否', () => {
  // 仕様の例（99.0 / 1.0-rc1 / didwebvh:1.0）に、旧版 0.4・旧メソッド名・大文字小文字違い・非文字列を加える。
  it.each([
    'did:webvh:0.4',
    'did:webvh:0.5',
    'did:tdw:0.3',
    'did:webvh:99.0',
    'did:webvh:1.0-rc1',
    'didwebvh:1.0',
    'DID:WEBVH:1.0',
    'did:webvh:1.0 ',
    '',
    1.0,
    null,
    { value: 'did:webvh:1.0' },
  ])('初版の method=%p は解決できない', async (method) => {
    const key = generateKey();
    const { did, entry } = forgeGenesis({ key, parameters: { method } });
    await expect(resolveLog(did, [signEntry(entry, key)])).rejects.toThrow(INVALID_DID);
  });

  it('初版に method が無いログは拒否する（既定値に落とさない）', async () => {
    const key = generateKey();
    const { did, entry } = forgeGenesis({ key, parameters: { method: undefined } });
    await expect(resolveLog(did, [signEntry(entry, key)])).rejects.toThrow(INVALID_DID);
  });

  it('did:webvh:0.4 の Log（旧 SDK の生成物）は拒否する', async () => {
    const key = generateKey();
    const { did, logEntry } = createDidWebVh({
      domain: 'vericerts.io',
      updateKeys: [key.multikey],
    });
    // 生成物の method だけを旧版に差し替えて署名し直した、0.4 時代と同じ形のログ。
    const { did: legacyDid, entry } = forgeGenesis({
      key,
      parameters: { method: 'did:webvh:0.4' },
    });
    expect(did).not.toBe(legacyDid);
    expect(logEntry.parameters.method).toBe('did:webvh:1.0');
    await expect(resolveLog(legacyDid, [signEntry(entry, key)])).rejects.toThrow(INVALID_DID);
  });
});

describe('後続の版での method', () => {
  it('省略すれば前の値が続き、同じ値の再宣言も受理する', async () => {
    const { key, did, genesis } = signedGenesis();
    const v2 = signEntry(
      forgeNext(genesis, stateOf(did), { method: 'did:webvh:1.0', updateKeys: [key.multikey] }),
      key,
    );
    const v3 = appendSigned([genesis, v2], key);
    const { metadata } = await resolveLog(did, [genesis, v2, v3]);
    expect(metadata.versionId).toBe(v3.versionId);
  });

  it.each([
    'did:webvh:0.4',
    'did:webvh:0.5',
    'did:webvh:99.0',
    'did:webvh:1.0-rc1',
    'didwebvh:1.0',
    'did:tdw:0.3',
  ])('下位版・未知の版（%s）への変更は拒否する', async (method) => {
    const { key, did, genesis } = signedGenesis();
    const v2 = signEntry(
      forgeNext(genesis, stateOf(did), { method, updateKeys: [key.multikey] }),
      key,
    );
    await expect(resolveLog(did, [genesis, v2])).rejects.toThrow(INVALID_DID);
  });
});
