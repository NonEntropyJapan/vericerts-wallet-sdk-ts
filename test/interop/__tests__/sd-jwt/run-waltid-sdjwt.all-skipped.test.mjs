// test/interop/__tests__/sd-jwt/run-waltid-sdjwt.all-skipped.test.mjs
//
// 「全ペアが skipped なら fail に倒す」ガードの回帰テスト。
//
// SD-JWT 経路は `run-peer-matrix.mjs` / `lib/peer-clients.mjs` を経由せず `docker compose run` で直接起動するため、JWT-VC 側にある同形のガードをランナー自身が持つ必要がある。
// 全ペア skipped は walt.id の `baseUrl` が公開ホスト検査を通らない名前へ退行した合図で、skipped の
// ままだと Issue 自動起票の対象外になり、Offer→Receive→Present が一度も走らないまま Nightly が
// 緑になる（非ゲートの `waltid-sdjwt-next` では「新版が baseUrl 設定を無視する」という最もありがちな
// 退行がちょうどこの形で無言化し、新版検知が成立しなくなる）。
//
// 実行には Bun が必要:
//   bun test test/interop/__tests__/sd-jwt/run-waltid-sdjwt.all-skipped.test.mjs

import { describe, expect, it } from 'bun:test';
import { run } from '../../run-waltid-sdjwt.mjs';
import { deps, LOOPBACK_RESPONSE_URI_REQUEST, PAIR_ISSUE, PAIR_PRESENT } from './fixtures.mjs';

describe('run: 全ペア skipped は「実駆動されていない」合図として fail に倒す', () => {
  // `lib/peer-clients.mjs` の JWT-VC 側と同形のガード。SD-JWT 経路は run-peer-matrix.mjs を
  // 経由せず `docker compose run` で直接起動するため、ランナー自身が持つ。
  // skipped のままだと Issue 自動起票の対象外で、Offer→Receive→Present が一度も走らないまま
  // Nightly が緑になる（非ゲートの `waltid-sdjwt-next` では新版の退行がここで無言化する）。
  /** `baseUrl` が公開ホスト検査を通らない名前へ退行した状態（offer が loopback を指す）。 */
  const loopbackOffer = {
    createIssuerOfferImpl: async () => ({
      offerUri: `openid-credential-offer://?credential_offer_uri=${encodeURIComponent(
        'https://localhost:8097/draft13/credentialOffer?id=abc',
      )}`,
      issuerPublicKeyJwk: { kty: 'OKP', crv: 'Ed25519', x: 'fake' },
    }),
  };

  it('offer が公開ホスト検査で拒否され 2 ペアとも skipped になったら両ペアを fail に倒す', async () => {
    let receiveCalled = false;
    const output = await run(
      deps({
        ...loopbackOffer,
        receiveCredentialImpl: async () => {
          receiveCalled = true;
          return { raw: 'unused' };
        },
      }),
    );
    expect(output.results.map((r) => r.status)).toEqual(['fail', 'fail']);
    // 元の skip 理由は失われず、両ペアの理由に連結して残る（退行の原因を Issue から辿れる）。
    for (const result of output.results) {
      expect(result.reason).toContain('全ペアが skipped になった（実駆動されていない）');
      expect(result.reason).toContain('loopback host is rejected by SDK public-host guard');
      expect(result.reason).toContain('提示する SD-JWT VC が無い');
    }
    // fail に倒しても実ピアへは接続しない（駆動前 skip の判定自体は変えない）。
    expect(receiveCalled).toBe(false);
  });

  it('倒した fail のペア名には接尾辞が付く（新版検知 job の結果が pinned 側と混ざらない）', async () => {
    const output = await run(deps({ ...loopbackOffer, pairSuffix: ':next' }));
    expect(output.results.map((r) => r.pair)).toEqual([
      `${PAIR_ISSUE}:next`,
      `${PAIR_PRESENT}:next`,
    ]);
    expect(output.results.map((r) => r.status)).toEqual(['fail', 'fail']);
  });

  it('regression: fail へ倒しても causedBy を落とさない（同根が 2 件起票されない）', async () => {
    // 全ペア skipped を fail へ倒すと、2 ペアとも**同じ理由**の fail になる。
    // `causedBy` を落とすと起票側が同根と判定できず、同じ原因で Issue が 2 件立つ。
    const output = await run(deps({ ...loopbackOffer }));
    expect(output.results.map((r) => r.status)).toEqual(['fail', 'fail']);
    expect(output.results[0].causedBy).toBeUndefined();
    expect(output.results[1].causedBy).toBe(PAIR_ISSUE);
  });

  it('一部だけ skipped（もう一方が pass）なら倒さない', async () => {
    const output = await run(
      deps({
        createVerifierRequestImpl: async () => LOOPBACK_RESPONSE_URI_REQUEST,
      }),
    );
    expect(output.results.map((r) => r.status)).toEqual(['pass', 'skipped']);
    expect(output.results[1].reason).not.toContain('全ペアが skipped');
  });

  it('skipped が 1 件も無い fail は理由を塗り潰されない（本来の失敗理由が消えない）', async () => {
    const output = await run(
      deps({
        createIssuerOfferImpl: async () => {
          throw new Error('offer failed: waltid unreachable');
        },
      }),
    );
    expect(output.results.map((r) => r.status)).toEqual(['fail', 'fail']);
    expect(output.results[0].reason).toBe('offer failed: waltid unreachable');
  });
});
