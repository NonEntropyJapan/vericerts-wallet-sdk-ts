/**
 * Status List Token の鮮度判定（`iat` / `ttl` と rollback ガード）。
 *
 * Token は署名付きなので配信経路（CDN・ミラー・第三者ホスト）を信頼しなくてよいはずだが、`exp` しか
 * 見ない解決器では、失効**前**に発行された正規署名の古い Token（`exp` 無し）を再生されると失効済み VC が
 * `valid` に戻る。`exp` を付けない発行が既定のため、再生は無期限に効く。ここでは次の 3 点で塞ぐ:
 *
 * 1. 未来の `iat`（`now + skew` 超）は拒否する（`CLOCK_SKEW_EXCEEDED` 4014）。
 * 2. 取得した Token の年齢 `now - iat` が上限以上なら拒否する（`VC_EXPIRED` 3024）。上限は Token の
 *    `ttl` クレームがあればそれ、無ければ解決器の `maxTokenAgeSeconds`（既定 24 時間）。
 * 3. URI ごとに観測した最大 `iat` を記憶し、それより古い `iat` の Token を拒否する（rollback ガード）。
 *
 * 判定は**新規取得分**にだけ課す。FO-2 で stale な Token を再利用するときは署名と sub を確かめて
 * ビット値を読む。通常のキャッシュ利用では格納時に TTL を
 * {@link effectiveExpSeconds} で切り詰めることで古い Token を返さない。
 */

import { CLOCK_SKEW_PROFILE } from '../../credential/time-claims.js';
import { ErrorCodes, VericertsError } from '../../errors.js';
import { ownProperty } from '../../prototype-safety/own-property.js';
import type { VerifiedStatusListToken } from '../status-list-token-verify.js';

/** `ttl` を持たない Token の年齢上限の既定値（24 時間）。 */
export const DEFAULT_STATUS_TOKEN_MAX_AGE_SECONDS = 24 * 60 * 60;

/** rollback ガードが記憶する URI 数の上限。超過時は最も古く記憶した URI から捨てる。 */
export const MAX_TRACKED_STATUS_LIST_URIS = 1024;

/** 解決器 1 つぶんの鮮度判定器。 */
export interface StatusListFreshness {
  /**
   * 新規取得した（署名・`sub` 検証済みの）Token が新しいことを確かめ、観測した `iat` を記録する。
   *
   * @throws `iat` が未来側にずれている場合（code `4014`）、年齢が上限以上 / `iat` が既観測の最大値より
   *         古い / 時計が有限でない場合（code `3024`）。
   */
  admitFetched(uri: string, token: VerifiedStatusListToken, nowSeconds: number): void;
  /** キャッシュの TTL 切り詰めに使う実効期限（`exp` と `iat + 年齢上限` の早い方）。 */
  effectiveExpSeconds(token: VerifiedStatusListToken): number;
}

/**
 * `maxTokenAgeSeconds` を検証して解決する。
 *
 * @throws 正の整数でない場合（code `3002`）。
 */
export function resolveMaxTokenAgeSeconds(requested: number | undefined): number {
  if (requested === undefined) {
    return DEFAULT_STATUS_TOKEN_MAX_AGE_SECONDS;
  }
  if (!Number.isSafeInteger(requested) || requested <= 0) {
    throw new VericertsError(ErrorCodes.VC_SCHEMA_INVALID);
  }
  return requested;
}

/**
 * 鮮度判定器を作る。
 *
 * @param maxTokenAgeSeconds `ttl` を持たない Token に課す年齢上限（`resolveMaxTokenAgeSeconds` 済み）。
 */
export function createStatusListFreshness(maxTokenAgeSeconds: number): StatusListFreshness {
  /** URI → これまでに受理した Token の最大 `iat`。Map の挿入順で古いものから捨てる。 */
  const maxSeenIat = new Map<string, number>();
  const ageLimit = (token: VerifiedStatusListToken): number =>
    // own 限定（`Object.prototype.ttlSeconds` / `expSeconds` の汚染で鮮度上限が延びない）。
    ownProperty<number>(token, 'ttlSeconds') ?? maxTokenAgeSeconds;

  return {
    admitFetched(uri, token, nowSeconds) {
      if (!Number.isFinite(nowSeconds)) {
        throw new VericertsError(ErrorCodes.VC_EXPIRED);
      }
      if (token.iatSeconds > nowSeconds + CLOCK_SKEW_PROFILE.vc) {
        throw new VericertsError(ErrorCodes.CLOCK_SKEW_EXCEEDED);
      }
      if (nowSeconds - token.iatSeconds >= ageLimit(token)) {
        throw new VericertsError(ErrorCodes.VC_EXPIRED);
      }
      const seen = maxSeenIat.get(uri);
      if (seen !== undefined && token.iatSeconds < seen) {
        throw new VericertsError(ErrorCodes.VC_EXPIRED);
      }
      // 再挿入で記憶順を更新し、上限超過時は最も古い URI を捨てる。
      maxSeenIat.delete(uri);
      maxSeenIat.set(uri, Math.max(seen ?? 0, token.iatSeconds));
      if (maxSeenIat.size > MAX_TRACKED_STATUS_LIST_URIS) {
        const oldest = maxSeenIat.keys().next();
        if (!oldest.done) {
          maxSeenIat.delete(oldest.value);
        }
      }
    },
    effectiveExpSeconds(token) {
      const byAge = token.iatSeconds + ageLimit(token);
      const expSeconds = ownProperty<number>(token, 'expSeconds');
      return expSeconds === undefined ? byAge : Math.min(expSeconds, byAge);
    },
  };
}
