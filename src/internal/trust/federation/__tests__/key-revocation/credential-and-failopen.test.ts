/**
 * 鍵無効化宣言の VC への適用（`assertCredentialKeyNotRevoked`）と fail-open 非適用。
 *
 * 検証内容:
 * - assertCredentialKeyNotRevoked: VC の `iat` が T 未満なら受理、T 以降なら 5012
 *   （Statement 側の `now` 基準とは異なり、VC は過去の事実の記録なので `iat` 基準）。
 * - verifyTrustAnchor は無効化ケースで false を返す（送出しない）。
 * - fail-open は適用されない: FailSafePolicy をどう設定しても 5012 は緩められず、
 *   実装が fail-open ゲート（resolveFailOpen / failsafe）に配線されていないことを構造的に検査する。
 */

import { describe, expect, it } from 'bun:test';
import { readFileSync } from 'node:fs';
import { ErrorCodes, VericertsError } from '../../../../errors.js';
import type { FailSafePolicy } from '../../../../failsafe/index.js';
import { FAIL_OPEN_IDS } from '../../../../failsafe/index.js';
import { assertKeyNotRevoked } from '../../revocation/key-revocation.js';
import { verifyTrustAnchor } from '../../trust-anchor-verify.js';
import { assertCredentialKeyNotRevoked, buildTrustChain } from '../../trust-chain.js';
import { NOW_SECONDS } from '../federation-fixtures.js';
import {
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

/**
 * VC 側は Statement 側と違い **VC の `iat` 基準**である。
 *
 * VC は第三者（Issuer）が発行した過去の事実の記録なので、`now` 基準にすると漏洩前に正当に発行された
 * VC まで巻き添えで無効化される。ここではローテート済みの旧鍵（チェーン構築は妨げない）を使い、
 * 「Statement は通るが VC は `iat` で切られる」分業が成立することを確かめる。
 */
describe('assertCredentialKeyNotRevoked', () => {
  /** 旧鍵についての宣言を持つ、成立するチェーンを組む。 */
  async function rotatedChain(): Promise<Awaited<ReturnType<typeof buildTrustChain>>> {
    const responses = buildTopology(NOW_SECONDS - 3600, ROTATED_DECLARATION);
    return await buildTrustChain(LEAF_ID, ANCHOR_ID, deps(responses));
  }

  it('VC の iat が無効化時刻より前なら受理する（now 基準にしてはならない）', async () => {
    const chain = await rotatedChain();
    expect(() =>
      assertCredentialKeyNotRevoked(chain, ROTATED_OUT_KID, REVOKED_AT - 1),
    ).not.toThrow();
  });

  it('VC の iat が無効化時刻以降なら FEDERATION_KEY_REVOKED', async () => {
    const chain = await rotatedChain();
    for (const iat of [REVOKED_AT, REVOKED_AT + 1, NOW_SECONDS]) {
      let caught: unknown;
      try {
        assertCredentialKeyNotRevoked(chain, ROTATED_OUT_KID, iat);
      } catch (error) {
        caught = error;
      }
      expect((caught as VericertsError).code).toBe(ErrorCodes.FEDERATION_KEY_REVOKED);
    }
  });

  it('宣言対象外の kid は受理する', async () => {
    const chain = await rotatedChain();
    expect(() => assertCredentialKeyNotRevoked(chain, 'other-key', NOW_SECONDS)).not.toThrow();
  });
});

describe('verifyTrustAnchor - 鍵無効化ケース', () => {
  it('無効化された Leaf は false を返す（送出しない）', async () => {
    const responses = buildTopology(REVOKED_AT + 60, COMPROMISE_DECLARATION);
    expect(await verifyTrustAnchor(LEAF_ID, ANCHOR_ID, deps(responses))).toBe(false);
  });

  it('無効化されていない Leaf は true を返す', async () => {
    const responses = buildTopology(NOW_SECONDS - 3600, ROTATED_DECLARATION);
    expect(await verifyTrustAnchor(LEAF_ID, ANCHOR_ID, deps(responses))).toBe(true);
  });

  // バイパスの回帰: iat 基準の頃はこの構成が true になり、失効鍵でエンティティ認証が通っていた。
  it('EC の iat を詐称した無効化済み Leaf も false を返す', async () => {
    const responses = buildTopology(REVOKED_AT - 1, COMPROMISE_DECLARATION);
    expect(await verifyTrustAnchor(LEAF_ID, ANCHOR_ID, deps(responses))).toBe(false);
  });
});

describe('FC-11 は fail-open で緩められない', () => {
  /** 全 FO-ID を escalate / suppressPrompt に列挙した最大限の override 設定。 */
  const permissivePolicy: FailSafePolicy = {
    escalate: FAIL_OPEN_IDS,
    suppressPrompt: FAIL_OPEN_IDS,
  };

  it('FailSafePolicy をどう設定しても assertKeyNotRevoked は拒否する', () => {
    // 判定は policy を引数に取らない（= 設定で通す余地が無い）ことを、policy を保持したまま確認する。
    expect(permissivePolicy.escalate?.length).toBeGreaterThan(0);
    expect(permissivePolicy.suppressPrompt?.length).toBeGreaterThan(0);
    expect(() =>
      assertKeyNotRevoked(
        [{ sub: LEAF_ID, kid: LEAF_KID, revoked_at: REVOKED_AT }],
        LEAF_ID,
        LEAF_KID,
        REVOKED_AT,
      ),
    ).toThrow(VericertsError);
  });

  it('buildTrustChain は policy 引数を取らず、常に 5012 で拒否する', async () => {
    const responses = buildTopology(REVOKED_AT + 60, COMPROMISE_DECLARATION);
    // buildTrustChain の依存注入は fetchFn / now のみで、fail-safe の override 口を持たない。
    expect(Object.keys(deps(responses)).sort()).toEqual(['fetchFn', 'now']);
    await expectRejectCode(
      buildTrustChain(LEAF_ID, ANCHOR_ID, deps(responses)),
      ErrorCodes.FEDERATION_KEY_REVOKED,
    );
  });

  it('実装が fail-open ゲートに配線されていない（配線されたら失敗する）', () => {
    // FC-11 は fail-closed。将来 resolveFailOpen を経由させる
    // 変更が入ったらこのテストが落ちる。
    const sources = [
      '../../revocation/key-revocation.ts',
      '../../trust-chain.ts',
      '../../revocation/trust-chain-revocation.ts',
      // Trust Anchor の EC 解決から FO-6 関連 deps を落とす経路。
      // ここに fail-open ゲートへの配線が紛れ込むと、アンカー EC にまで FO-6 が
      // 及び得る＝FC-11 相当の無効化経路が無いアンカーで stale な鍵を通してしまう。
      '../../fail-open/trust-chain-anchor-deps.ts',
      // VC 検証経路への配線。fail-closed の保証はこちらでも構造的に守る。
      '../../../../credential/issuer-key-revocation.ts',
    ];
    for (const path of sources) {
      const source = readFileSync(new URL(path, import.meta.url), 'utf8');
      // JSDoc 中の言及と、実行時に消える型専用 import / re-export（`TrustChain.warnings` が
      // 参照する `FailSafeWarning`）は許容し、**値**としての import / re-export /
      // 呼び出しのみを禁止する。`import ... from` だけでなく `export { resolveFailOpen } from`
      // のような re-export 形式も同じ危険を持つため検知対象に含める。
      // import / export は相対深さがファイルごとに異なるため、`../` の反復として照合する。
      expect(source).not.toMatch(/^(?:import|export) (?!type )[^;]*from '(\.\.\/)+failsafe/m);
      expect(source).not.toContain('resolveFailOpen(');
      expect(source).not.toContain('decideFailSafe(');
    }
  });
});
