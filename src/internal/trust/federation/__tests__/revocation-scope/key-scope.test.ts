/**
 * 鍵無効化宣言の突合スコープの回帰テスト。
 *
 * 検証内容:
 * - 宣言は**宣言対象の subject に閉じる**。`kid` は 1 つの JWKS 内でしか一意でないため、
 *   別エンティティ宛の宣言が同名 `kid` を使う無関係な署名を巻き添えにしてはならない（誤検知の回帰）。
 * - 失効させられた鍵が**実際に署名した Subordinate Statement** をチェーン内で拒否する。
 *   子の Entity Configuration の `iat` だけを見ていると、`iat` を詐称した中間者が失効鍵で
 *   新しい Subordinate Statement を発行し放題になる（見逃しの回帰）。
 * - 署名鍵の突合は **`iat` ではなく検証時刻 `now`** を基準とする。`iat` は失効させられた当の鍵の
 *   保有者が自己申告する値で古さに上限が無い。発行時刻が失効前で、有効期限が将来の値でも、
 *   検証時刻に失効していれば拒否する。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes } from '../../../../errors.js';
import { assertCredentialKeyNotRevoked, buildTrustChain } from '../../trust-chain.js';
import { NOW_SECONDS } from '../federation-fixtures.js';
import {
  ANCHOR_ID,
  expectRejectCode,
  INTERMEDIATE_ID,
  LEAF_ID,
  REVOKED_AT,
  topologyDeps,
} from './harness.js';

/** Leaf と Intermediate が偶然同じ `kid` を使っている構成。 */
const SHARED_KID = '1';

describe('宣言は subject に閉じる（誤検知の回帰）', () => {
  /**
   * Anchor が **Intermediate について** `kid: "1"` を失効させた構成。
   * Leaf も偶然 `kid: "1"` を使っているが、Leaf は宣言の対象ではない。
   */
  function crossEntityCollision(): ReturnType<typeof topologyDeps> {
    return topologyDeps({
      leafKid: SHARED_KID,
      intermediateKid: 'int-1',
      // Leaf の EC は無効化時刻以降に発行されている（宣言が Leaf に及ぶなら拒否される時刻）。
      leafIat: REVOKED_AT + 60,
      intermediateIat: REVOKED_AT - 100,
      intAboutLeafIat: REVOKED_AT - 100,
      anchorRevokedKeys: [{ kid: SHARED_KID, revoked_at: REVOKED_AT, reason: 'key_compromise' }],
    });
  }

  it('別エンティティ宛の宣言は Trust Chain 構築を妨げない', async () => {
    const chain = await buildTrustChain(LEAF_ID, ANCHOR_ID, crossEntityCollision());
    expect(chain.valid).toBe(true);
  });

  it('集約された宣言は宣言対象（Intermediate）の sub を保持する', async () => {
    const chain = await buildTrustChain(LEAF_ID, ANCHOR_ID, crossEntityCollision());
    expect(chain.revokedKeys).toEqual([
      {
        sub: INTERMEDIATE_ID,
        kid: SHARED_KID,
        revoked_at: REVOKED_AT,
        reason: 'key_compromise',
      },
    ]);
  });

  // 回帰の中心: sub を捨てて kid だけで突合すると、Leaf 発行の VC がここで 5012 になる。
  it('Leaf 発行の VC は同名 kid でも拒否されない（既定の subject は chain.leaf）', async () => {
    const chain = await buildTrustChain(LEAF_ID, ANCHOR_ID, crossEntityCollision());
    expect(() => assertCredentialKeyNotRevoked(chain, SHARED_KID, REVOKED_AT + 3600)).not.toThrow();
  });

  it('宣言対象（Intermediate）を明示すれば同じ kid で拒否される', async () => {
    const chain = await buildTrustChain(LEAF_ID, ANCHOR_ID, crossEntityCollision());
    let caught: unknown;
    try {
      assertCredentialKeyNotRevoked(chain, SHARED_KID, REVOKED_AT + 3600, INTERMEDIATE_ID);
    } catch (error) {
      caught = error;
    }
    expect((caught as { code?: string } | undefined)?.code).toBe(ErrorCodes.FEDERATION_KEY_REVOKED);
  });
});

describe('失効鍵が署名した Subordinate Statement を拒否する（見逃しの回帰）', () => {
  /**
   * `L → I → TA` で TA が `I` の `kid: "int-1"` を時刻 T で失効させた構成。
   *
   * `I` は自分の Entity Configuration に `iat = T - 100`（失効前）を書いて子の EC 検査を回避し、
   * その一方で失効した鍵を使い `iat = T + 60`（失効後）の Subordinate Statement を Leaf に発行する。
   * 子の Entity Configuration の `iat` しか見ない実装ではこのチェーンが成立してしまう。
   */
  function revokedSignerTopology(): ReturnType<typeof topologyDeps> {
    return topologyDeps({
      leafKid: 'leaf-1',
      intermediateKid: 'int-1',
      leafIat: NOW_SECONDS - 3600,
      // 失効時刻より前を自己申告して assertChildKeysNotRevoked を通過する。
      intermediateIat: REVOKED_AT - 100,
      // 失効した鍵で、失効時刻以降に発行された Subordinate Statement。
      intAboutLeafIat: REVOKED_AT + 60,
      anchorRevokedKeys: [{ kid: 'int-1', revoked_at: REVOKED_AT, reason: 'key_compromise' }],
    });
  }

  it('失効鍵で署名された Subordinate Statement は FEDERATION_KEY_REVOKED（5012）で拒否する', async () => {
    await expectRejectCode(
      buildTrustChain(LEAF_ID, ANCHOR_ID, revokedSignerTopology()),
      ErrorCodes.FEDERATION_KEY_REVOKED,
    );
  });

  it('例外に kid・entity id・URL を漏らさない', async () => {
    const error = await expectRejectCode(
      buildTrustChain(LEAF_ID, ANCHOR_ID, revokedSignerTopology()),
      ErrorCodes.FEDERATION_KEY_REVOKED,
    );
    const serialized = `${error.message}${JSON.stringify(error.context ?? {})}`;
    for (const secret of ['int-1', LEAF_ID, INTERMEDIATE_ID, ANCHOR_ID, 'https://']) {
      expect(serialized).not.toContain(secret);
    }
  });

  /**
   * 失効鍵の保有者が `iat` を詐称して両検査を回避しようとする構成（バイパスの回帰）。
   *
   * `assertStatementTimeValid` は `iat <= now < exp` しか見ず `iat` の古さに上限が無いため、
   * `I` は Subordinate Statement の `iat` を `revoked_at - 1`、`exp` を将来に置くだけで
   * 「失効前に署名された Statement」を自称できる。`iat` 基準で突合していた頃はこの構成が
   * `chain.valid === true` になり、失効鍵で TA 配下に任意の leaf を新規発行できてしまった。
   *
   * 突合を検証時刻 `now` 基準にしたことで、`revoked_at <= now` である限り申告 `iat` は効かない。
   */
  it('iat を失効時刻の直前に詐称した Subordinate Statement も拒否する（now 基準の回帰）', async () => {
    await expectRejectCode(
      buildTrustChain(
        LEAF_ID,
        ANCHOR_ID,
        topologyDeps({
          leafKid: 'leaf-1',
          intermediateKid: 'int-1',
          leafIat: NOW_SECONDS - 3600,
          // 自己申告の `iat` はいずれも失効時刻より前。`exp` は harness が常に NOW + 3600 に置く。
          intermediateIat: REVOKED_AT - 100,
          intAboutLeafIat: REVOKED_AT - 1,
          anchorRevokedKeys: [{ kid: 'int-1', revoked_at: REVOKED_AT }],
        }),
      ),
      ErrorCodes.FEDERATION_KEY_REVOKED,
    );
  });

  // now 基準にしても「まだ失効していない鍵」まで拒否しないことの確認（過剰拒否の回帰）。
  it('失効時刻が未来（now < revoked_at）ならチェーンは成立する', async () => {
    const chain = await buildTrustChain(
      LEAF_ID,
      ANCHOR_ID,
      topologyDeps({
        leafKid: 'leaf-1',
        intermediateKid: 'int-1',
        leafIat: NOW_SECONDS - 3600,
        intermediateIat: NOW_SECONDS - 3600,
        intAboutLeafIat: NOW_SECONDS - 3600,
        anchorRevokedKeys: [{ kid: 'int-1', revoked_at: NOW_SECONDS + 600 }],
      }),
    );
    expect(chain.valid).toBe(true);
  });
});
