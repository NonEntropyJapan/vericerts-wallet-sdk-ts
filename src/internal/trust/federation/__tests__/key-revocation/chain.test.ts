/**
 * 鍵無効化宣言（`revoked_keys`）の Trust Chain 構築への反映。
 *
 * 検証内容:
 * - 鍵漏洩シナリオ（回帰テスト）: Trust Anchor が Leaf 鍵を時刻 T で無効化宣言したとき、
 *   `T <= now` である限り Leaf EC の `iat` に関わらず FEDERATION_KEY_REVOKED（5012。5010 ではない）。
 *   Entity Configuration は自己署名で `iat` も自己申告のため、`iat` 基準では `iat = T - 1` への
 *   詐称で素通りできてしまう（バイパスの回帰）。
 * - 過剰拒否の回帰: 無効化時刻が未来（`now < T`）ならチェーンは成立する。
 * - 宣言が無い / kid が異なる（ローテート済みで EC に載っていない）場合はチェーンが成立する。
 * - `TrustChain.revokedKeys` に Subordinate Statement の宣言が集約される（退化ケースは空配列）。
 * - `revoked_keys` の構造不正は Statement の構造不正（5010）として拒否される。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes } from '../../../../errors.js';
import { buildTrustChain } from '../../trust-chain.js';
import { NOW_SECONDS } from '../federation-fixtures.js';
import {
  ANCHOR_FETCH,
  ANCHOR_ID,
  buildTopology,
  COMPROMISE_DECLARATION,
  deps,
  expectRejectCode,
  LEAF_ID,
  LEAF_KID,
  REVOKED_AT,
  ROTATED_DECLARATION,
  ROTATED_OUT_KID,
} from './harness.js';

describe('buildTrustChain - 鍵漏洩シナリオ（回帰テスト）', () => {
  // バイパスの回帰: `iat` 基準で判定していた頃、この構成は chain.valid === true になっていた。
  // Leaf EC は自己署名なので `iat` は失効させられた当の鍵の保有者の自己申告であり、`revoked_at - 1`
  // に詐称するだけで検査を素通りできた。しかも leaf は自分が署名した Subordinate Statement を
  // チェーンに持たないため `assertChainSignaturesNotRevoked` の網にも掛からず、失効鍵のまま
  // エンティティ認証が通っていた。
  it('Leaf EC の iat を無効化時刻の直前に詐称してもチェーンは成立しない（now 基準の回帰）', async () => {
    const responses = buildTopology(REVOKED_AT - 1, COMPROMISE_DECLARATION);
    await expectRejectCode(
      buildTrustChain(LEAF_ID, ANCHOR_ID, deps(responses)),
      ErrorCodes.FEDERATION_KEY_REVOKED,
    );
  });

  // 過剰拒否の回帰: `now` 基準にしても、まだ失効していない鍵まで拒否してはならない。
  it('無効化時刻が未来（now < T）ならチェーンは成立する', async () => {
    const responses = buildTopology(NOW_SECONDS - 3600, [
      { kid: LEAF_KID, revoked_at: NOW_SECONDS + 600 },
    ]);
    const chain = await buildTrustChain(LEAF_ID, ANCHOR_ID, deps(responses));
    expect(chain.valid).toBe(true);
    expect(chain.leaf).toBe(LEAF_ID);
  });

  // ローテート済みの旧鍵についての宣言は、現行 EC に載っていない以上チェーンを妨げない。
  it('EC に載っていない旧鍵についての宣言はチェーンを妨げない', async () => {
    const responses = buildTopology(NOW_SECONDS - 3600, ROTATED_DECLARATION);
    const chain = await buildTrustChain(LEAF_ID, ANCHOR_ID, deps(responses));
    expect(chain.valid).toBe(true);
  });

  it('Leaf EC の iat が無効化時刻ちょうどなら FEDERATION_KEY_REVOKED（境界を含む）', async () => {
    const responses = buildTopology(REVOKED_AT, COMPROMISE_DECLARATION);
    await expectRejectCode(
      buildTrustChain(LEAF_ID, ANCHOR_ID, deps(responses)),
      ErrorCodes.FEDERATION_KEY_REVOKED,
    );
  });

  it('Leaf EC の iat が無効化時刻より後なら FEDERATION_KEY_REVOKED（5010 に正規化しない）', async () => {
    const responses = buildTopology(REVOKED_AT + 60, COMPROMISE_DECLARATION);
    const error = await expectRejectCode(
      buildTrustChain(LEAF_ID, ANCHOR_ID, deps(responses)),
      ErrorCodes.FEDERATION_KEY_REVOKED,
    );
    expect(error.code).toBe('5012');
    expect(error.code).not.toBe(ErrorCodes.TRUST_CHAIN_INVALID);
  });

  it('別 kid の宣言では Leaf 鍵は無効化されない', async () => {
    const responses = buildTopology(REVOKED_AT + 60, [
      { kid: 'other-key', revoked_at: REVOKED_AT },
    ]);
    const chain = await buildTrustChain(LEAF_ID, ANCHOR_ID, deps(responses));
    expect(chain.valid).toBe(true);
  });

  it('例外に kid・entity id・URL を漏らさない', async () => {
    const responses = buildTopology(REVOKED_AT + 60, COMPROMISE_DECLARATION);
    const error = await expectRejectCode(
      buildTrustChain(LEAF_ID, ANCHOR_ID, deps(responses)),
      ErrorCodes.FEDERATION_KEY_REVOKED,
    );
    const serialized = `${error.message}${JSON.stringify(error.context ?? {})}`;
    for (const secret of [LEAF_KID, LEAF_ID, ANCHOR_ID, ANCHOR_FETCH, 'https://']) {
      expect(serialized).not.toContain(secret);
    }
  });
});

describe('TrustChain.revokedKeys の集約', () => {
  it('Subordinate Statement の宣言が集約される', async () => {
    const responses = buildTopology(NOW_SECONDS - 3600, ROTATED_DECLARATION);
    const chain = await buildTrustChain(LEAF_ID, ANCHOR_ID, deps(responses));
    // 宣言には対象 subject（= Subordinate Statement の `sub` = Leaf）が紐付く。
    expect(chain.revokedKeys).toEqual([
      { sub: LEAF_ID, kid: ROTATED_OUT_KID, revoked_at: REVOKED_AT, reason: 'key_compromise' },
    ]);
  });

  it('宣言が無ければ空配列になる', async () => {
    const responses = buildTopology(REVOKED_AT - 1);
    const chain = await buildTrustChain(LEAF_ID, ANCHOR_ID, deps(responses));
    expect(chain.revokedKeys).toEqual([]);
  });

  it('Leaf 自身が Trust Anchor の退化ケースでも空配列になる', async () => {
    const responses = buildTopology(REVOKED_AT - 1);
    const chain = await buildTrustChain(LEAF_ID, LEAF_ID, deps(responses));
    expect(chain.length).toBe(1);
    expect(chain.revokedKeys).toEqual([]);
  });
});

describe('revoked_keys の構造不正', () => {
  it('宣言が配列でなければ Statement の構造不正（5010）として拒否する', async () => {
    const responses = buildTopology(REVOKED_AT - 1, { kid: LEAF_KID, revoked_at: REVOKED_AT });
    await expectRejectCode(
      buildTrustChain(LEAF_ID, ANCHOR_ID, deps(responses)),
      ErrorCodes.TRUST_CHAIN_INVALID,
    );
  });

  it('revoked_at が不正な宣言は黙って読み飛ばさず 5010 で拒否する', async () => {
    const responses = buildTopology(REVOKED_AT - 1, [{ kid: LEAF_KID, revoked_at: -1 }]);
    await expectRejectCode(
      buildTrustChain(LEAF_ID, ANCHOR_ID, deps(responses)),
      ErrorCodes.TRUST_CHAIN_INVALID,
    );
  });
});
