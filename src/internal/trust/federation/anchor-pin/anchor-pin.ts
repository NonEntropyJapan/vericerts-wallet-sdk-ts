/**
 * OIDF Trust Anchor の鍵ピン留め（trust/federation）。
 *
 * OpenID Federation 1.0 の Trust Anchor は「Entity Identifier **と公開鍵**を事前に（out-of-band で）
 * 設定したもの」で、チェーンの根は設定された鍵による署名で拘束される。Trust Anchor の Entity
 * Configuration は自己署名（payload 内の自己 `jwks` が鍵源）なので、ピン留めが無いと根拠は
 * 「`trustAnchor` URL への TLS 接続」だけになり、TLS を破れる攻撃者が任意の鍵で自己署名した
 * Anchor EC と Subordinate Statement を返すだけで任意の leaf が Trust Anchor 配下になる。
 *
 * ピン留め（`BuildTrustChainOptions.trustAnchorJwks`）が指定された場合、Anchor の EC は次を満たす:
 *  1. 自己 `jwks` に、設定された鍵のいずれかと**鍵素材が一致する鍵**を含む。
 *  2. その一致した鍵（設定された鍵）で EC の署名が成立する。
 * 未指定の場合は従来どおり（自己署名のみ）で、`TrustChain.anchorPinned` が `false` になる。
 *
 * セキュリティ上の注意: 例外メッセージ・`context` に鍵・URL・JWT を含めない。
 */

import type { DecodedJws } from '../../../credential/vc/jws.js';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import { ownProperty } from '../../../prototype-safety/own-property.js';
import type { EntityConfiguration, JsonWebKeySet } from '../federation-types.js';
import { decodeStatementJws, verifyDecodedStatement } from '../statement/statement.js';
import { consumeStatementBudget, type StatementBudget } from '../statement/statement-budget.js';
import { isPinnedJwkSet, keyMaterialOf } from './pinned-jwks.js';

/** `buildTrustChain` の追加オプション。 */
export interface BuildTrustChainOptions {
  /**
   * Trust Anchor の公開鍵（JWK Set）。out-of-band で設定した鍵で、Anchor の Entity Configuration が
   * この鍵のいずれかで署名され、かつ自己 `jwks` に含まれていることを要求する。
   * 未指定ならピン留めしない（`TrustChain.anchorPinned: false`）。空の `keys` は未指定扱いにせず拒否する。
   */
  readonly trustAnchorJwks?: JsonWebKeySet;
}

/**
 * 設定されたピン留め鍵を検証して返す。
 *
 * @throws `keys` が非空配列でない / 鍵素材を読めない鍵を含む場合（TRUST_CHAIN_INVALID。fail-closed）。
 */
export function parsePinnedJwks(options: BuildTrustChainOptions): JsonWebKeySet | undefined {
  const jwks = ownProperty<unknown>(options, 'trustAnchorJwks');
  if (jwks === undefined) {
    return undefined;
  }
  if (!isPinnedJwkSet(jwks)) {
    throw new VericertsError(ErrorCodes.TRUST_CHAIN_INVALID);
  }
  return jwks;
}

/**
 * Trust Anchor の Entity Configuration が、ピン留め鍵で署名され、その鍵を自己 `jwks` に含むことを確認する。
 *
 * @param anchorConfig 検証済み（自己署名）の Anchor Entity Configuration。
 * @param pinned `parsePinnedJwks` で検証済みのピン留め鍵。
 * @param budget Trust Chain 構築 1 回ぶんの Statement 本文量の予算（省略時は計上しない）。
 * @throws ピン留め鍵のいずれでも署名が成立しない / 自己 `jwks` に含まれない場合（TRUST_CHAIN_INVALID）。
 */
export function assertAnchorPinned(
  anchorConfig: EntityConfiguration,
  pinned: JsonWebKeySet,
  budget?: StatementBudget,
): void {
  let decoded: DecodedJws | undefined;
  for (const declared of anchorConfig.statement.jwks.keys) {
    const material = keyMaterialOf(declared);
    const pinnedKey = pinned.keys.find((key) => keyMaterialOf(key) === material);
    if (material === undefined || pinnedKey === undefined) {
      continue;
    }
    // `kid` は鍵の同一性ではなくラベルなので、Anchor が宣言した `kid`（JWS ヘッダの `kid` 照合に使われる）を
    // 当てて、鍵素材は**ピン留めした側**のものだけで検証する。
    // 宣言鍵ごとに JWT を JSON パースし直さない。鍵源の候補が見つかった時点で 1 回だけデコードする。
    if (decoded === undefined) {
      consumeStatementBudget(budget, anchorConfig.jwt);
      decoded = decodeStatementJws(anchorConfig.jwt);
    }
    const declaredKid = ownProperty<unknown>(declared, 'kid');
    const { kid: _ignored, ...pinnedMaterial } = pinnedKey as Record<string, unknown>;
    const verifyKey = (typeof declaredKid === 'string'
      ? { ...pinnedMaterial, kid: declaredKid }
      : pinnedMaterial) as unknown as JsonWebKeySet['keys'][number];
    try {
      verifyDecodedStatement(decoded, { keys: [verifyKey] });
      return;
    } catch {
      // この鍵では署名が成立しない。次の宣言鍵を試す。
    }
  }
  throw new VericertsError(ErrorCodes.TRUST_CHAIN_INVALID);
}
