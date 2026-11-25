/**
 * 信頼アンカー検証（`verifyTrustAnchor`。`trust-chain.ts` から 1 ファイル行数上限のため分離）。
 */

import { ErrorCodes, VericertsError } from '../../errors.js';
import {
  type BuildTrustChainDeps,
  type BuildTrustChainOptions,
  buildTrustChain,
} from './trust-chain.js';

/**
 * Leaf が指定 Trust Anchor 配下にあることを検証する（信頼アンカー検証）。
 *
 * `buildTrustChain` を試行し、成立すれば `true`、Trust Chain 不成立（TRUST_CHAIN_INVALID）および
 * 鍵無効化宣言に該当（FEDERATION_KEY_REVOKED）なら `false` を返す。取得失敗
 * （FEDERATION_FETCH_FAILED）等の再試行可能なエラーは呼び出し側で扱えるようそのまま送出する。
 *
 * FEDERATION_KEY_REVOKED を `false` に写すのは、鍵漏洩の宣言があった時点で「この Leaf は当該 Trust
 * Anchor 配下ではない」という本関数の問いへの答えが確定するため。到達不能とは意味が異なるので、
 * 想定外の例外として素通りさせず捕捉対象へ明示的に加える。5012 の詳細（漏洩か単なる到達不能か）を
 * 区別したい呼び出し側は `buildTrustChain` を直接使う。
 *
 * **鍵ピン留めの扱い:** `options.trustAnchorJwks` を渡すと `buildTrustChain` と同じく Anchor の
 * Entity Configuration がその鍵で署名され自己 `jwks` に含まれることを要求し、満たさなければ `false`
 * （不正な設定値も未指定へ倒さず `false`）。**省略した場合の `true` は Anchor の自己署名と TLS だけを
 * 根拠にする**（TLS を破れる攻撃者が自己署名の Anchor と Subordinate Statement を返せば成立する）。
 * 戻り値は boolean のため両者を区別できない。区別が要る呼び出し側は `buildTrustChain` の
 * `TrustChain.anchorPinned` を使う。
 *
 * @param entityId Leaf の Entity Identifier。
 * @param trustAnchor Trust Anchor の Entity Identifier。
 * @param deps 依存注入。
 * @param options `trustAnchorJwks`: Trust Anchor の公開鍵のピン留め（`buildTrustChain` の第 4 引数と同じ）。
 * @returns Trust Anchor 配下であれば `true`。
 * @throws Entity Configuration 取得失敗等の再試行可能なエラー（VericertsError、FEDERATION_FETCH_FAILED）。
 */
export async function verifyTrustAnchor(
  entityId: string,
  trustAnchor: string,
  deps: BuildTrustChainDeps = {},
  options: BuildTrustChainOptions = {},
): Promise<boolean> {
  // 「Trust Anchor 配下でない」ことが確定するコード。いずれも false（例外ではない）で返す。
  const notUnderAnchor: readonly string[] = [
    ErrorCodes.TRUST_CHAIN_INVALID,
    ErrorCodes.FEDERATION_KEY_REVOKED,
  ];
  try {
    const chain = await buildTrustChain(entityId, trustAnchor, deps, options);
    return chain.valid;
  } catch (error) {
    if (error instanceof VericertsError && notUnderAnchor.includes(error.code)) {
      return false;
    }
    throw error;
  }
}
