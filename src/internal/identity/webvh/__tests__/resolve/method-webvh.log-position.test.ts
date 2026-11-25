/**
 * did:webvh の proof のログ位置束縛と、失効（deactivated）後の追記拒否の回帰テスト。
 *
 * - 署名対象に `versionId` が入っておらず、ホストを制御する攻撃者が過去の署名済みエントリの
 *   `{versionTime, parameters, state, proof}` を複製して `versionId` だけ再計算して追記すると、
 *   鍵無しで DID を過去版へ巻き戻せた（失効済みの検証鍵の復活）。署名対象を v1.0 の式（`versionId` を含むエントリ全体）に
 *   したため、旧方式の `proof.challenge === versionId` の検査は持たない。位置の束縛は署名・entryHash の連鎖・連番・
 *   versionTime の厳密な単調増加が担い、ここでその再送が拒否されることを固定する（署名対象から versionId を外すと、位置への署名束縛・公開されなかった候補の再送・再送（低層）のテストが落ちる）。
 * - `deactivated: true` の行より後の追記が受理され、失効を取り消せた。
 */

import { afterEach, describe, expect, it } from 'bun:test';
import {
  entryWithoutProof,
  updateKeysOf,
  type WebVhLogEntry,
  type WebVhProof,
} from '../../codec.js';
import { resolveDidWebVh, updateDidWebVh } from '../../method-webvh.js';
import { documentHashOf, verifyEntryProof, verifyProofSignature } from '../../proof.js';
import {
  forgeAppendEntry,
  generateKey,
  mockFetchOnce,
  restoreFetch,
  signEntry,
  type TestKey,
  toJsonl,
} from '../webvh-fixtures.js';
import {
  buildGenesis,
  buildReplay,
  buildRotatedV2,
  INVALID_DID,
  repositioned,
} from './log-position-fixtures.js';

afterEach(() => {
  restoreFetch();
});

describe('did:webvh proof のログ位置束縛（署名が versionId を含むエントリにかかる）', () => {
  // 再送（既存の署名済み版を後続位置へ複製）: resolve 経由。
  it('過去の署名済みエントリを複製して versionId だけ再計算した再送は INVALID_DID', async () => {
    const { did, signedGenesis, signedV2, replayed } = buildReplay(generateKey());
    mockFetchOnce(toJsonl([signedGenesis, signedV2, replayed]));

    await expect(resolveDidWebVh(did)).rejects.toThrow(INVALID_DID);
  });

  // 再送（低層）: versionTime の単調増加検査や連番検査を通らずに、署名検証だけで再送が落ちる。
  it('再送エントリは versionTime の検査と無関係に、proof の署名検証で拒否される', () => {
    const { signedGenesis, replayed } = buildReplay(generateKey());

    expect(() => verifyEntryProof(replayed, updateKeysOf(replayed))).toThrow(INVALID_DID);
    // 元の位置（初版）では有効なまま。
    expect(() => verifyEntryProof(signedGenesis, updateKeysOf(signedGenesis))).not.toThrow();
  });

  // 位置への署名束縛（versionId だけの差し替え）: 署名が位置（versionId）に束縛される。versionId 以外は 1 バイトも変えない。
  it('署名済みエントリの versionId だけを別の位置のものに替えると、署名検証が失敗する', () => {
    const key = generateKey();
    const { signedGenesis, signedV2 } = buildReplay(key);
    const proof = (signedGenesis.proof as readonly WebVhProof[])[0] as WebVhProof;
    const hashOf = (entry: WebVhLogEntry) => documentHashOf(entryWithoutProof(entry));
    const moved = [
      repositioned(signedGenesis, 3, signedV2.versionId),
      repositioned(signedGenesis, 2, signedGenesis.versionId),
      { ...signedGenesis, versionId: `1-Qm${'A'.repeat(44)}` },
    ];

    // 元の位置では、署名単体も proof 検証も通る（挙動対照）。
    expect(verifyProofSignature(proof, hashOf(signedGenesis), key.multikey)).toBe(true);
    expect(() => verifyEntryProof(signedGenesis, updateKeysOf(signedGenesis))).not.toThrow();
    for (const entry of moved) {
      expect(entry.versionId).not.toBe(signedGenesis.versionId);
      expect(verifyProofSignature(proof, hashOf(entry), key.multikey)).toBe(false);
      expect(() => verifyEntryProof(entry, updateKeysOf(entry))).toThrow(INVALID_DID);
    }
  });

  // 公開されなかった候補の再送: 公開されなかった候補 A（versionTime が B より新しく、正規に署名済み）を 3 番目に差し込む。
  // 署名対象から versionId を外すと（旧 SDK 式）受理され、失効した #A が復活する。
  it('versionTime が新しい別の署名済みエントリ（公開されなかった候補）の再送は INVALID_DID（失効した鍵の復活を防ぐ）', async () => {
    const key = generateKey();
    const { did, signedGenesis } = buildGenesis(key);
    const genesisTime = Date.parse(signedGenesis.versionTime);
    const at = (offsetMs: number) => new Date(genesisTime + offsetMs).toISOString();
    // B: #A を失効させた公開版（t+10s）。A: #A を残したまま（復活させる状態）の候補（t+20s）。どちらも位置 2 の候補で正規署名。
    const rotated = buildRotatedV2(did, signedGenesis, key).state;
    const signedB = signEntry(forgeAppendEntry([signedGenesis], rotated, at(10_000)), key);
    const signedA = signEntry(
      forgeAppendEntry([signedGenesis], { ...signedGenesis.state }, at(20_000)),
      key,
    );
    const replayedA = repositioned(signedA, 3, signedB.versionId);

    // 対照: A は元の位置（2 番目）では正規に解決でき、#A を持つ。B は #A を持たない。
    mockFetchOnce(toJsonl([signedGenesis, signedA]));
    expect((await resolveDidWebVh(did)).verificationMethod?.length).toBe(1);
    mockFetchOnce(toJsonl([signedGenesis, signedB]));
    expect((await resolveDidWebVh(did)).verificationMethod?.length).toBe(0);
    // 時刻の列は単調増加（t < t+10s < t+20s）で、versionTime の検査だけでは落ちない。
    expect(Date.parse(replayedA.versionTime)).toBeGreaterThan(Date.parse(signedB.versionTime));

    mockFetchOnce(toJsonl([signedGenesis, signedB, replayedA]));
    await expect(resolveDidWebVh(did)).rejects.toThrow(INVALID_DID);
    expect(() => verifyEntryProof(replayedA, updateKeysOf(replayedA))).toThrow(INVALID_DID);
  });
});

describe('did:webvh versionTime の単調増加', () => {
  it('versionTime が前版以前のエントリは、正規署名でも INVALID_DID', async () => {
    const key = generateKey();
    const { did, signedGenesis } = buildGenesis(key);
    const v2 = forgeAppendEntry(
      [signedGenesis],
      { ...signedGenesis.state },
      signedGenesis.versionTime,
    );
    mockFetchOnce(toJsonl([signedGenesis, signEntry(v2, key)]));

    await expect(resolveDidWebVh(did)).rejects.toThrow(INVALID_DID);
  });

  it('未来の versionTime は INVALID_DID', async () => {
    const key = generateKey();
    const { did, signedGenesis } = buildGenesis(key);
    const v2 = forgeAppendEntry(
      [signedGenesis],
      { ...signedGenesis.state },
      new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(),
    );
    mockFetchOnce(toJsonl([signedGenesis, signEntry(v2, key)]));

    await expect(resolveDidWebVh(did)).rejects.toThrow(INVALID_DID);
  });

  it('versionTime が ISO 8601 でないエントリは INVALID_DID', async () => {
    const key = generateKey();
    const { did, signedGenesis } = buildGenesis(key);
    const v2 = forgeAppendEntry([signedGenesis], { ...signedGenesis.state }, 'not-a-date');
    mockFetchOnce(toJsonl([signedGenesis, signEntry(v2, key)]));

    await expect(resolveDidWebVh(did)).rejects.toThrow(INVALID_DID);
  });

  // versionTime の UTC 限定: spec Read (Resolve) 4。versionTime は UTC を明示する `Z`（または `+00:00`）に限る。時刻の列は単調増加でも拒否される。
  it('versionTime が UTC 以外のオフセット・ゾーン指定なしのエントリは INVALID_DID（同じ時刻を指していても）', async () => {
    const key = generateKey();
    const { did, signedGenesis } = buildGenesis(key);
    const instant = Date.parse(signedGenesis.versionTime) + 10_000;
    const utcPlus9 = new Date(instant + 9 * 60 * 60 * 1000).toISOString().replace('Z', '+09:00');
    const noZone = new Date(instant).toISOString().replace('Z', '');
    const zeroOffset = new Date(instant).toISOString().replace('Z', '+00:00');
    const draftAt = (versionTime: string) =>
      signEntry(forgeAppendEntry([signedGenesis], { ...signedGenesis.state }, versionTime), key);

    for (const versionTime of [utcPlus9, noZone]) {
      mockFetchOnce(toJsonl([signedGenesis, draftAt(versionTime)]));
      await expect(resolveDidWebVh(did)).rejects.toThrow(INVALID_DID);
    }
    mockFetchOnce(toJsonl([signedGenesis, draftAt(zeroOffset)]));
    expect((await resolveDidWebVh(did)).id).toBe(did);
  });

  it('既定の versionTime で連続生成した正当なチェーン（同一ミリ秒内）は解決できる', async () => {
    const key = generateKey();
    const { did, signedGenesis } = buildGenesis(key);
    const signedV2 = buildRotatedV2(did, signedGenesis, key);
    mockFetchOnce(toJsonl([signedGenesis, signedV2]));

    const doc = await resolveDidWebVh(did);
    expect(doc.verificationMethod).toEqual([]);
  });
});

describe('did:webvh 失効（deactivated）後の追記拒否', () => {
  /** v1 → deactivated な d2 の署名済み 2 行を作る。 */
  function buildDeactivatedLog(key: TestKey): {
    did: string;
    signedGenesis: WebVhLogEntry;
    signedD2: WebVhLogEntry;
  } {
    const { did, signedGenesis } = buildGenesis(key);
    const d2 = updateDidWebVh({
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
    return { did, signedGenesis, signedD2: signEntry(d2, key) };
  }

  it('同じ鍵で署名した deactivated:false の再有効化エントリを追記したログは INVALID_DID', async () => {
    const key = generateKey();
    const { did, signedGenesis, signedD2 } = buildDeactivatedLog(key);
    const r3 = forgeAppendEntry(
      [signedGenesis, signedD2],
      {
        '@context': ['https://www.w3.org/ns/did/v1'],
        id: did,
        verificationMethod: [
          {
            id: `${did}#attacker`,
            type: 'Multikey',
            controller: did,
            publicKeyMultibase: 'zATTACKER',
          },
        ],
        authentication: [],
        assertionMethod: [],
      },
      // d2 より後かつ未来でない時刻（versionTime 規則ではなく失効後追記そのものを検証する）。
      new Date(Date.now() + 1000).toISOString(),
    );
    mockFetchOnce(toJsonl([signedGenesis, signedD2, signEntry(r3, key)]));

    await expect(resolveDidWebVh(did)).rejects.toThrow(INVALID_DID);
  });

  it('失効後に deactivated を省略した追記（state 上は有効に見える）も INVALID_DID', async () => {
    const key = generateKey();
    const { did, signedGenesis, signedD2 } = buildDeactivatedLog(key);
    const r3 = forgeAppendEntry(
      [signedGenesis, signedD2],
      { ...signedGenesis.state },
      // d2 より後かつ未来でない時刻（versionTime 規則ではなく失効後追記そのものを検証する）。
      new Date(Date.now() + 1000).toISOString(),
    );
    mockFetchOnce(toJsonl([signedGenesis, signedD2, signEntry(r3, key)]));

    await expect(resolveDidWebVh(did)).rejects.toThrow(INVALID_DID);
  });

  it('失効行までのログは引き続き有効で、versionId 指定による失効前版の解決は維持される', async () => {
    const key = generateKey();
    const { did, signedGenesis, signedD2 } = buildDeactivatedLog(key);
    mockFetchOnce(toJsonl([signedGenesis, signedD2]));

    const doc = await resolveDidWebVh(did, { versionId: signedGenesis.versionId });
    expect(doc.id).toBe(did);
    // 最新版（失効行）の解決は拒否される。
    await expect(resolveDidWebVh(did)).rejects.toThrow(INVALID_DID);
  });
});
