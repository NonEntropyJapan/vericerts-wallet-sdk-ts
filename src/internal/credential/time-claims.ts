/**
 * 時刻クレーム（`iat` / `exp` / `nbf`）の共通評価とクロックスキュープロファイル。
 *
 * JWT-VC / JWT-VP / SD-JWT VC / KB-JWT の時刻検証はすべて本モジュールの定数と評価ロジックを共有する
 * （フォーマットごとに許容スキューが食い違うと、緩い経路が時刻検証の bypass になるため）。
 * DPoP proof（`verifyDpopProof`）も `CLOCK_SKEW_PROFILE.dpopProof` と `resolveClockSkewSeconds` を
 * 共有するが、共有するのはオプションの上限キャップ検査（`4015`）のみで、時刻判定そのものの
 * エラーコードは DPoP 固有である（`iat` の窓外は `4082`、型不正は `4080`）。
 *
 * DPoP-bound session token の `token`（±60秒）は予約値で、現在の SDK には対応する検証経路がない。
 *
 * セキュリティ上の注意:
 * - 例外メッセージや `context` に payload・クレーム値・JWT を含めない。
 */

import { assertFiniteClock } from '../cache/system-clock.js';
import { ErrorCodes, VericertsError } from '../errors.js';
import { ownProperty } from '../prototype-safety/own-property.js';

/**
 * 種別ごとの既定クロックスキュー秒数（= テナントが指定できる上限キャップ）。
 *
 * 種別ごとに、既定値以下の秒数を指定できる。上限を超える値は
 * `4015 CLOCK_SKEW_OPTION_INVALID` で拒否する。
 */
export const CLOCK_SKEW_PROFILE = {
  /** JWT-VC / SD-JWT VC（Issuer-signed JWT）。 */
  vc: 120,
  /** JWT-VP。 */
  vp: 30,
  /** KB-JWT（`iat` のみ）。 */
  kbJwt: 30,
  /**
   * DPoP proof JWT（`typ: dpop+jwt`）の `iat`。
   *
   * `verifyDpopProof` の `clockSkewSeconds`（未来方向）と `maxAgeSeconds`（過去方向）は同じ ±30 s
   * 窓の左右半分なので、双方に本キャップを適用する。DPoP-bound session token（`token`）とは
   * 別の検証対象であり、30秒の上限は proof に適用される。
   */
  dpopProof: 30,
  /** DPoP-bound session token（現時点で SDK に検証実装なし・仕様パリティのみ）。 */
  token: 60,
} as const;

/** `CLOCK_SKEW_PROFILE` の種別キー。 */
export type ClockSkewKind = keyof typeof CLOCK_SKEW_PROFILE;

/**
 * テナント指定のクロックスキュー秒数を検証し、実効値へ解決する。
 *
 * 未指定なら種別の既定値（= キャップ）を返す。指定値は「非負整数かつキャップ以下」のみ受理し、
 * 非整数・負値・非数値・`NaN` / `Infinity`・キャップ超過はすべて拒否する
 * （`Number.isInteger` が非数値・非有限を一括で弾く）。
 *
 * @param kind スキュー種別（`vc` / `vp` / `kbJwt` / `dpopProof` / `token`）。
 * @param requested テナント指定値（未指定なら `undefined`）。
 * @returns 実効クロックスキュー秒数。
 * @throws 指定値が非負整数でない / キャップを超える場合（VericertsError、code `4015`）。
 */
export function resolveClockSkewSeconds(
  kind: ClockSkewKind,
  requested: number | undefined,
): number {
  const cap = CLOCK_SKEW_PROFILE[kind];
  if (requested === undefined) {
    return cap;
  }
  if (!Number.isInteger(requested) || requested < 0 || requested > cap) {
    throw new VericertsError(ErrorCodes.CLOCK_SKEW_OPTION_INVALID);
  }
  return requested;
}

/**
 * JWT payload の `iat` / `exp` / `nbf` をクロックスキュー込みで評価する（全フォーマット共通）。
 *
 * NumericDate（エポック秒）の数値とし、存在するクレームのみ評価する（未設定は従来どおり成功）。
 * skew は「評価時刻をずらす」形で適用する:
 * - `iat > now + skew` → `CLOCK_SKEW_EXCEEDED`（4014）。過去方向は本関数では制限しない。
 * - `now - skew >= exp` → `VC_EXPIRED`（3024）。JWT 慣行の `>=` を維持するため境界値ちょうどは拒否する。
 * - `now + skew < nbf` → `VC_NOT_YET_VALID`（3025）。境界値ちょうどは受理する。
 * - いずれも型不正（非数値・非有限）は `VC_SCHEMA_INVALID`（3002）。
 *
 * 評価順は `iat` → `exp` → `nbf` で固定する。時計が進んだ端末のトークンは `exp` / `nbf` の判定自体が
 * 無意味になるため、先に `iat` を見て 4014（時計ずれと分かる診断的なコード）を返す。
 *
 * @param payload デコード済み JWS payload。
 * @param nowSeconds 現在時刻（エポック秒）。
 * @param skewSeconds 実効クロックスキュー秒数（`resolveClockSkewSeconds` の戻り値）。
 * @throws スキュー超過（code `4014`）/ 期限切れ（code `3024`）/ 有効化前（code `3025`）/
 *         時刻型不正（code `3002`）の場合（VericertsError）。`nowSeconds` / `skewSeconds` が有限数でない
 *         場合は fail-closed で `4015`（`assertFiniteClock`）。
 */
export function assertTimeClaims(
  payload: Record<string, unknown>,
  nowSeconds: number,
  skewSeconds: number,
): void {
  assertFiniteClock(nowSeconds);
  assertFiniteClock(skewSeconds);
  // 呼び出し元 3 経路（`credential/vc/verify.ts` / `credential/sdjwt/verify.ts` /
  // `credential/presentation/presentation.ts`）はいずれも `decodeCompactJws` →
  // `identity/jwt/jwt-codec.ts` の `parseJson` → `parse-json.ts` の `parseJsonWithoutPrototype`
  // を通した payload を渡すため **`null` プロトタイプ**である。own 限定で読むのはその手法と**重畳する多層防御**で、
  // 分割代入のような鎖読みへ戻すと、パース境界を通らない payload の流入時に当該クレームを
  // 持たないものでも `Object.prototype` の汚染値を「クレーム値」として拾い、時刻検証が汚染側へ
  // 倒れる。
  // 3 クレームとも純データ（NumericDate）なので `ownProperty` でよい。
  const iat = ownProperty<unknown>(payload, 'iat');
  const exp = ownProperty<unknown>(payload, 'exp');
  const nbf = ownProperty<unknown>(payload, 'nbf');
  if (iat !== undefined) {
    if (typeof iat !== 'number' || !Number.isFinite(iat)) {
      throw new VericertsError(ErrorCodes.VC_SCHEMA_INVALID);
    }
    if (iat > nowSeconds + skewSeconds) {
      throw new VericertsError(ErrorCodes.CLOCK_SKEW_EXCEEDED);
    }
  }
  if (exp !== undefined) {
    if (typeof exp !== 'number' || !Number.isFinite(exp)) {
      throw new VericertsError(ErrorCodes.VC_SCHEMA_INVALID);
    }
    if (nowSeconds - skewSeconds >= exp) {
      throw new VericertsError(ErrorCodes.VC_EXPIRED);
    }
  }
  if (nbf !== undefined) {
    if (typeof nbf !== 'number' || !Number.isFinite(nbf)) {
      throw new VericertsError(ErrorCodes.VC_SCHEMA_INVALID);
    }
    if (nowSeconds + skewSeconds < nbf) {
      throw new VericertsError(ErrorCodes.VC_NOT_YET_VALID);
    }
  }
}
