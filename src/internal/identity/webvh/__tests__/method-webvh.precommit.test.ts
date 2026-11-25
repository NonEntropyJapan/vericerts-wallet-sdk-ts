/**
 * 鍵事前コミット（nextKeyHashes）と versionId ピン時の deactivated 意味論の
 * 検証テスト。実 Ed25519 署名で構築した DID Log を `globalThis.fetch` モック経由で解決する。
 *
 * did:webvh v1.0（spec: `nextKeyHashes` / Authorized Keys / Read (Resolve) 7）: 事前コミット中は
 * - 次版は `updateKeys` と `nextKeyHashes` を**両方とも明示**する（継承不可・`updateKeys` は空にできない）、
 * - `updateKeys` の**全部**が前版の `nextKeyHashes` に含まれる、
 * - 次版の proof は**当該版の** `updateKeys` の鍵で署名する（事前コミットしていた新しい鍵で署名する）。
 */

import { afterEach, describe, expect, it } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import {
  deriveVersionId,
  nextVersionTime,
  type WebVhLogEntry,
  type WebVhParameters,
} from '../codec.js';
import {
  createDidWebVh,
  resolveDidWebVh,
  resolveDidWebVhWithMetadata,
  updateDidWebVh,
  updateKeyHash,
} from '../method-webvh.js';
import { generateKey, mockFetchOnce, restoreFetch, signEntry, toJsonl } from './webvh-fixtures.js';

const INVALID_DID = new VericertsError(ErrorCodes.INVALID_DID);

const STATE = (did: string) => ({
  '@context': ['https://www.w3.org/ns/did/v1'],
  id: did,
  verificationMethod: [],
  authentication: [],
  assertionMethod: [],
});

/** `parameters` を指定どおり（省略キーも含めて）に差し替え、versionId を再計算した版エントリを作る。 */
function entryWithParameters(
  previous: WebVhLogEntry,
  did: string,
  parameters: WebVhParameters,
): WebVhLogEntry {
  const draft: WebVhLogEntry = {
    versionId: '',
    // 連続生成でも versionTime が厳密増加になるようにする。
    versionTime: nextVersionTime(previous.versionTime),
    parameters,
    state: STATE(did),
  };
  const versionNumber = Number(previous.versionId.split('-')[0]) + 1;
  return { ...draft, versionId: deriveVersionId(draft, versionNumber, previous.versionId) };
}

afterEach(() => {
  restoreFetch();
});

/** 事前コミット付きの初版（K1 が署名、K2 を事前コミット）。 */
function committedGenesis(
  key1: ReturnType<typeof generateKey>,
  key2: ReturnType<typeof generateKey>,
  extra: Partial<Parameters<typeof createDidWebVh>[0]> = {},
) {
  const { did, logEntry } = createDidWebVh({
    domain: 'vericerts.io',
    updateKeys: [key1.multikey],
    nextKeyHashes: [updateKeyHash(key2.multikey)],
    ...extra,
  });
  return { did, signedGenesis: signEntry(logEntry, key1) };
}

describe('resolveDidWebVh 鍵事前コミット（nextKeyHashes）', () => {
  it('事前コミットした鍵へ、その鍵自身の署名でローテーションすれば解決できる', async () => {
    const key1 = generateKey();
    const key2 = generateKey();
    const { did, signedGenesis } = committedGenesis(key1, key2);
    const v2 = updateDidWebVh({
      previousLog: [signedGenesis],
      state: STATE(did),
      updateKeys: [key2.multikey],
      nextKeyHashes: [],
    });
    mockFetchOnce(toJsonl([signedGenesis, signEntry(v2, key2)]));

    const doc = await resolveDidWebVh(did);
    expect(doc.id).toBe(did);
  });

  it('事前コミット中は前版の鍵（K1）の署名を受け付けない（当該版の updateKeys の鍵で署名する）', async () => {
    const key1 = generateKey();
    const key2 = generateKey();
    const { did, signedGenesis } = committedGenesis(key1, key2);
    const v2 = updateDidWebVh({
      previousLog: [signedGenesis],
      state: STATE(did),
      updateKeys: [key2.multikey],
      nextKeyHashes: [],
    });
    mockFetchOnce(toJsonl([signedGenesis, signEntry(v2, key1)]));

    await expect(resolveDidWebVh(did)).rejects.toThrow(INVALID_DID);
  });

  it('事前コミットされていない鍵に 2 版目で差し替えると INVALID_DID（ビルダーも署名前に拒否する）', async () => {
    const key1 = generateKey();
    const key2 = generateKey();
    const rogue = generateKey();
    const { did, signedGenesis } = committedGenesis(key1, key2);
    expect(() =>
      updateDidWebVh({
        previousLog: [signedGenesis],
        state: STATE(did),
        updateKeys: [rogue.multikey],
        nextKeyHashes: [],
      }),
    ).toThrow(INVALID_DID);
    const forged = signEntry(
      entryWithParameters(signedGenesis, did, { updateKeys: [rogue.multikey], nextKeyHashes: [] }),
      rogue,
    );
    mockFetchOnce(toJsonl([signedGenesis, forged]));

    await expect(resolveDidWebVh(did)).rejects.toThrow(INVALID_DID);
  });

  it('updateKeys の全部が事前コミット済みでなければならない（新しく現れた鍵だけでなく既存の K1 も含めて）', async () => {
    const key1 = generateKey();
    const key2 = generateKey();
    const { did, signedGenesis } = committedGenesis(key1, key2);
    const forged = signEntry(
      entryWithParameters(signedGenesis, did, {
        updateKeys: [key2.multikey, key1.multikey],
        nextKeyHashes: [],
      }),
      key2,
    );
    mockFetchOnce(toJsonl([signedGenesis, forged]));

    await expect(resolveDidWebVh(did)).rejects.toThrow(INVALID_DID);
  });
});

describe('resolveDidWebVh 鍵事前コミットの省略による回避', () => {
  it('updateKeys / nextKeyHashes を省略した版で事前コミットを消し、次版で攻撃者鍵へ乗っ取る 3 版チェーンは INVALID_DID', async () => {
    const key1 = generateKey();
    const key2 = generateKey();
    const attacker = generateKey();
    const { did, signedGenesis } = committedGenesis(key1, key2);
    // 版 2: K1 署名、updateKeys も nextKeyHashes も省略（継承）。
    const v2 = signEntry(entryWithParameters(signedGenesis, did, {}), key1);
    // 版 3: K1 署名で攻撃者鍵へローテーション。
    const v3 = signEntry(entryWithParameters(v2, did, { updateKeys: [attacker.multikey] }), key1);
    mockFetchOnce(toJsonl([signedGenesis, v2, v3]));

    await expect(resolveDidWebVh(did)).rejects.toThrow(INVALID_DID);
  });

  it('事前コミット中に updateKeys・nextKeyHashes のどちらか一方でも省略した版は INVALID_DID', async () => {
    const key1 = generateKey();
    const key2 = generateKey();
    const { did, signedGenesis } = committedGenesis(key1, key2);
    const cases: [WebVhParameters, typeof key2][] = [
      [{}, key1],
      // updateKeys だけ省略（`updateKeys` を継承して K1 のまま回避しようとする）。
      [{ nextKeyHashes: [] }, key1],
      // nextKeyHashes だけ省略。
      [{ updateKeys: [key2.multikey] }, key2],
      // 空の updateKeys。
      [{ updateKeys: [], nextKeyHashes: [] }, key1],
    ];
    for (const [parameters, signer] of cases) {
      const v2 = signEntry(entryWithParameters(signedGenesis, did, parameters), signer);
      mockFetchOnce(toJsonl([signedGenesis, v2]));
      await expect(resolveDidWebVh(did)).rejects.toThrow(INVALID_DID);
    }
  });

  it('コミット済み鍵へローテーションした版が新しい nextKeyHashes を宣言すれば、そのコミットが次版を拘束する', async () => {
    const key1 = generateKey();
    const key2 = generateKey();
    const key3 = generateKey();
    const attacker = generateKey();
    const { did, signedGenesis } = committedGenesis(key1, key2);
    const v2 = signEntry(
      entryWithParameters(signedGenesis, did, {
        updateKeys: [key2.multikey],
        nextKeyHashes: [updateKeyHash(key3.multikey)],
      }),
      key2,
    );
    const rotated = signEntry(
      entryWithParameters(v2, did, { updateKeys: [key3.multikey], nextKeyHashes: [] }),
      key3,
    );
    mockFetchOnce(toJsonl([signedGenesis, v2, rotated]));
    expect((await resolveDidWebVh(did)).id).toBe(did);

    const rogue = signEntry(
      entryWithParameters(v2, did, { updateKeys: [attacker.multikey], nextKeyHashes: [] }),
      attacker,
    );
    mockFetchOnce(toJsonl([signedGenesis, v2, rogue]));
    await expect(resolveDidWebVh(did)).rejects.toThrow(INVALID_DID);
  });

  it('nextKeyHashes を空配列にすると事前コミットは解除され、以降は前版の鍵の署名で任意の鍵へ更新できる', async () => {
    const key1 = generateKey();
    const key2 = generateKey();
    const key3 = generateKey();
    const { did, signedGenesis } = committedGenesis(key1, key2);
    const v2 = signEntry(
      entryWithParameters(signedGenesis, did, { updateKeys: [key2.multikey], nextKeyHashes: [] }),
      key2,
    );
    // 事前コミットが解除された後は通常のルール: K2（前版の updateKeys）が署名し、K3 は事前コミット不要。
    const v3 = signEntry(entryWithParameters(v2, did, { updateKeys: [key3.multikey] }), key2);
    mockFetchOnce(toJsonl([signedGenesis, v2, v3]));

    const doc = await resolveDidWebVh(did);
    expect(doc.id).toBe(did);
  });
});

describe('resolveDidWebVh versionId ピン（deactivated 意味論）', () => {
  it('失効前の版を versionId でピンすると、後続版が失効していても state を返し、メタデータは失効を示す', async () => {
    const key = generateKey();
    const { did, logEntry: genesis } = createDidWebVh({
      domain: 'vericerts.io',
      updateKeys: [key.multikey],
    });
    const signedGenesis = signEntry(genesis, key);
    // 2 版目で失効させる（`parameters.deactivated`）。
    const v2 = updateDidWebVh({
      previousLog: [signedGenesis],
      state: STATE(did),
      deactivated: true,
    });
    mockFetchOnce(toJsonl([signedGenesis, signEntry(v2, key)]));

    // 失効前の初版をピンすれば、最新版が失効でも初版 state を取得できる。
    const resolution = await resolveDidWebVhWithMetadata(did, {
      versionId: signedGenesis.versionId,
    });
    expect(resolution.document.id).toBe(did);
    expect(resolution.metadata.deactivated).toBe(true);
    expect(resolution.metadata.versionId).toBe(signedGenesis.versionId);
  });
});
