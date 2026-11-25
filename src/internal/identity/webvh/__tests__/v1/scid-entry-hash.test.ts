/**
 * SCID・versionId（entryHash）・`state.id` の検証（did:webvh v1.0、spec: SCID Generation and Verification、
 * Entry Hash Generation and Verification、Read (Resolve) 3・5・6、The DID Log File の「検証に失敗する例」4・5）。
 */

import { afterEach, describe, expect, it } from 'bun:test';
import {
  deriveVersionId,
  entryWithoutProof,
  multihashOfText,
  type WebVhLogEntry,
} from '../../codec.js';
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

const OTHER_SCID = `Qm${'X'.repeat(44)}`;

/** `proof` を取り除いた上で任意に改変し、署名し直す。 */
function resign(
  entry: WebVhLogEntry,
  key: ReturnType<typeof generateKey>,
  patch: Partial<WebVhLogEntry>,
) {
  const { proof: _proof, ...rest } = entry;
  return signEntry({ ...rest, ...patch } as WebVhLogEntry, key);
}

describe('初版の versionId と SCID', () => {
  it('versionId は `1-<entryHash>` で、entryHash は SCID を直前の識別子にしたハッシュ（SCID とは別の値）', () => {
    const { did, genesis } = signedGenesis();
    const scid = genesis.parameters.scid as string;
    expect(did).toContain(`:${scid}:`);
    const [, entryHash] = genesis.versionId.split('-');
    expect(entryHash).not.toBe(scid);
    expect(genesis.versionId).toBe(deriveVersionId(genesis, 1, scid));
    // 仕様: JCS(proof を除くエントリ。versionId は直前の識別子 = 初版は SCID) の SHA-256 multihash。
    const hashInput = JSON.stringify({ ...entryWithoutProof(genesis), versionId: scid });
    expect(entryHash).toBe(multihashOfText(sortedJson(hashInput)));
  });

  it('SCID は preliminary entry（versionId と全 SCID が {SCID}）の JCS ハッシュで、DID・state 内の全出現が置換される', () => {
    const { genesis } = signedGenesis({
      document: {
        '@context': ['https://www.w3.org/ns/did/v1'],
        controller: 'did:webvh:{SCID}:vericerts.io',
        verificationMethod: [],
        authentication: [],
        assertionMethod: [],
      },
    });
    const scid = genesis.parameters.scid as string;
    expect(genesis.state.controller).toBe(`did:webvh:${scid}:vericerts.io`);
    expect(JSON.stringify(genesis)).not.toContain('{SCID}');
  });

  it('初版の state を改竄すると SCID の検証で拒否される（entryHash を直しても）', async () => {
    const { key, did, genesis } = signedGenesis();
    const tampered = resign(genesis, key, {
      state: { ...genesis.state, alsoKnownAs: ['https://evil.example'] },
    });
    const fixed = {
      ...tampered,
      versionId: deriveVersionId(tampered, 1, genesis.parameters.scid as string),
    };
    await expect(resolveLog(did, [signEntry(fixed, key)])).rejects.toThrow(INVALID_DID);
  });

  it('parameters.scid が DID の SCID と違うログは拒否される', async () => {
    const key = generateKey();
    const { entry } = forgeGenesis({ key });
    const { did: otherDid } = forgeGenesis({ key, state: { alsoKnownAs: ['x'] } });
    await expect(resolveLog(otherDid, [signEntry(entry, key)])).rejects.toThrow(INVALID_DID);
  });

  it('SCID が SHA-256 multihash でない（別のハッシュ・不正な長さ）なら拒否される', async () => {
    const key = generateKey();
    const { did, entry } = forgeGenesis({ key });
    const shortScid = 'QmShort';
    const forged = { ...entry, parameters: { ...entry.parameters, scid: shortScid } };
    await expect(resolveLog(did, [signEntry(forged, key)])).rejects.toThrow(INVALID_DID);
  });

  it('初版に parameters.scid が無いログは拒否される', async () => {
    const key = generateKey();
    const { did, entry } = forgeGenesis({ key });
    const { scid: _scid, ...parameters } = entry.parameters;
    await expect(resolveLog(did, [signEntry({ ...entry, parameters }, key)])).rejects.toThrow(
      INVALID_DID,
    );
  });
});

describe('entryHash の連鎖（全版で検証する）', () => {
  it('中間の版の entryHash を誤っていれば、最新版だけを解決しても拒否される', async () => {
    const { key, did, genesis } = signedGenesis();
    const v2 = appendSigned([genesis], key);
    const v3 = appendSigned([genesis, v2], key);
    const wrong = { ...v2, versionId: `2-Qm${'W'.repeat(44)}` };
    await expect(resolveLog(did, [genesis, signEntry(wrong, key), v3])).rejects.toThrow(
      INVALID_DID,
    );
  });

  it('版番号に欠番・重複があれば拒否される', async () => {
    const { key, did, genesis } = signedGenesis();
    const v2 = appendSigned([genesis], key);
    const gap = signEntry(
      { ...v2, versionId: `3-${v2.versionId.split('-')[1]}` } as WebVhLogEntry,
      key,
    );
    await expect(resolveLog(did, [genesis, gap])).rejects.toThrow(INVALID_DID);
    await expect(resolveLog(did, [genesis, genesis])).rejects.toThrow(INVALID_DID);
  });

  it.each([
    '2',
    '2-',
    '-Qm',
    '2-a-b',
    '02-Qm',
    'x-Qm',
  ])('形式の崩れた versionId（%s）は拒否される', async (versionId) => {
    const { key, did, genesis } = signedGenesis();
    const v2 = appendSigned([genesis], key);
    await expect(resolveLog(did, [genesis, signEntry({ ...v2, versionId }, key)])).rejects.toThrow(
      INVALID_DID,
    );
  });

  it('entryHash が SHA-256 multihash でない（SHA-512 など別のアルゴリズム・不正な長さ）なら拒否される', async () => {
    const { key, did, genesis } = signedGenesis();
    const v2 = appendSigned([genesis], key);
    // 0x13（sha2-512）の multihash を装った 46 文字の値。
    const other = `2-Qm${'1'.repeat(44)}`;
    await expect(
      resolveLog(did, [genesis, signEntry({ ...v2, versionId: other }, key)]),
    ).rejects.toThrow(INVALID_DID);
  });

  // entryHash 連鎖（本文改竄）: 署名済みの版の本文だけを書き換える（versionId も proof もそのまま）。
  it('本文（state）を書き換えて versionId を再計算しない版は、entryHash の不一致で拒否される', async () => {
    const { key, did, genesis } = signedGenesis();
    const v2 = appendSigned([genesis], key);
    const tampered = { ...v2, state: { ...v2.state, alsoKnownAs: ['https://example.com/x'] } };
    await expect(resolveLog(did, [genesis, v2])).resolves.toBeDefined();
    await expect(resolveLog(did, [genesis, tampered])).rejects.toThrow(INVALID_DID);
  });

  // entryHash 連鎖（署名の不一致）: 本文を書き換えて versionId を再計算しても、proof（署名）は旧本文・旧 versionId のものなので合わない。
  it('本文を書き換えて versionId を再計算しただけ（署名は旧）の版は、署名の不一致で拒否される', async () => {
    const { key, did, genesis } = signedGenesis();
    const v2 = appendSigned([genesis], key);
    const draft = { ...v2, state: { ...v2.state, alsoKnownAs: ['https://example.com/x'] } };
    const tampered = {
      ...draft,
      versionId: deriveVersionId(draft, 2, genesis.versionId),
    };
    expect(tampered.versionId).not.toBe(v2.versionId);
    await expect(resolveLog(did, [genesis, tampered])).rejects.toThrow(INVALID_DID);
    // 同じ本文に正しく署名し直せば受理される（拒否の理由が署名であることの対照）。
    await expect(resolveLog(did, [genesis, resign(tampered, key, {})])).resolves.toBeDefined();
  });

  // entryHash 連鎖（版の欠落・並べ替え）: 途中の版の削除・並べ替え・先頭の欠落。
  it('中間の版の削除・並べ替え・初版の欠落は拒否される', async () => {
    const { key, did, genesis } = signedGenesis();
    const v2 = appendSigned([genesis], key);
    const v3 = appendSigned([genesis, v2], key);
    await expect(resolveLog(did, [genesis, v2, v3])).resolves.toBeDefined();
    await expect(resolveLog(did, [genesis, v3])).rejects.toThrow(INVALID_DID);
    await expect(resolveLog(did, [genesis, v3, v2])).rejects.toThrow(INVALID_DID);
    await expect(resolveLog(did, [v2, v3])).rejects.toThrow(INVALID_DID);
  });
});

describe('全版の state.id の SCID（spec 検証例 4・5）', () => {
  it('後続の版の state.id が別の SCID を持つログは拒否される（portable でも）', async () => {
    const { key, did, genesis } = signedGenesis({ portable: true });
    const moved = stateOf(`did:webvh:${OTHER_SCID}:new.example.com`, { alsoKnownAs: [did] });
    const v2 = signEntry(forgeNext(genesis, moved, { updateKeys: [key.multikey] }), key);
    await expect(resolveLog(did, [genesis, v2])).rejects.toThrow(INVALID_DID);
  });

  it('state.id が DID として不正（did:webvh でない・DID URL）な版は拒否される', async () => {
    const { key, did, genesis } = signedGenesis();
    for (const id of ['did:web:vericerts.io', `${did}#key-1`, `${did}/path`, 42, undefined]) {
      const v2 = signEntry(
        forgeNext(genesis, { ...genesis.state, id } as never, { updateKeys: [key.multikey] }),
        key,
      );
      await expect(resolveLog(did, [genesis, v2])).rejects.toThrow(INVALID_DID);
    }
  });

  it('解決対象の DID と一致する state.id が 1 つも無いログ（SCID だけ同じ別の場所の DID）は拒否される', async () => {
    const { did, genesis } = signedGenesis();
    const elsewhere = did.replace(':vericerts.io', ':other.example.com');
    expect(elsewhere).not.toBe(did);
    await expect(resolveLog(elsewhere, [genesis])).rejects.toThrow(INVALID_DID);
  });
});

/** JSON 文字列を JCS（キーのコードポイント順）に直す（テスト側の独立実装）。 */
function sortedJson(text: string): string {
  const sort = (value: unknown): unknown =>
    Array.isArray(value)
      ? value.map(sort)
      : value !== null && typeof value === 'object'
        ? Object.fromEntries(
            Object.entries(value as Record<string, unknown>)
              .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
              .map(([k, v]) => [k, sort(v)]),
          )
        : value;
  return JSON.stringify(sort(JSON.parse(text)));
}
