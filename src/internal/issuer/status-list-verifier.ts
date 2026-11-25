/**
 * Verifier 側の Status List 運用ヘルパー（キャッシュ TTL 評価とステータス判定）。
 *
 * IETF draft-ietf-oauth-status-list に基づく。
 *
 * Status List Token は全 VC 分のビット列を 1 本の JWT で配信するため、Verifier は毎回取得せず
 * キャッシュするのが前提になる。一方で失効指示は一定時間内に反映されなければならないので、
 * 「キャッシュをいつまで使ってよいか」を決める TTL の評価が運用上の要になる。
 *
 * 本モジュールは次を提供する:
 * - `evaluateCacheFreshness`: 取得時刻・`Cache-Control: max-age`・Token の `exp`・**呼び出し側が
 *   指定する TTL 上限**から、キャッシュが有効かと残り秒数を求める。
 * - `parseMaxAgeSeconds`: `Cache-Control` ヘッダから `max-age` を取り出す（実体は
 *   `internal/cache/ttl-cache.ts`。ここでは後方互換のため再エクスポートする）。
 * - `evaluateStatusEntry`: `StatusCheckResult` を `valid` / `revoked` / `suspended` に判定する。
 *
 * 本モジュールが提供するのは上記の評価プリミティブのみで、キャッシュ本体（エントリの保持・
 * negative cache）は汎用の `internal/cache/ttl-cache.ts`、Status List への配線は
 * `status-list-cache.ts` / `status-list-resolver.ts`が持つ。`evaluateCacheFreshness`
 * は配線側からも呼ばれ、`exp` による切り詰めの規則をここ 1 箇所に集約する。
 *
 * fail-safe の射程: 配信側が長い `max-age` を返しても上限で切り詰めるため、**配信側が返す
 * `max-age` に対しては** Issuer の設定ミスが反映遅延に直結しない。ただし上流キャッシュ（CDN・
 * 中間キャッシュ）で既に経過した時間（レスポンスの `Age`）は本モジュールの評価対象外であり、
 * これだけでは真の反映上界は得られない。上界を締めるには Token 自身の `exp`（`expSeconds`）を
 * 渡す（`status-list-resolver.ts` は取得した Token の `exp` を必ず渡している）。
 *
 * セキュリティ上の注意:
 * - 例外メッセージや `context` に URL・インデックス・ビット値・JWT を含めない。
 */

import type { StatusCheckResult } from '../credential/sdjwt/status.js';
import { ErrorCodes, VericertsError } from '../errors.js';
import { ownProperty } from '../prototype-safety/own-property.js';
import { STATUS_VALUE_VALID } from './status-list-types.js';

/**
 * `Cache-Control` ヘッダの `max-age` パーサ。
 *
 * 実体は共通キャッシュ層（`internal/cache/ttl-cache.ts`）に移設した。
 * did:web / Status List / Federation Entity Statement で同一の解釈が必要なためである。
 * 既存の公開名を維持するためここから再エクスポートする。
 */
export { parseMaxAgeSeconds } from '../cache/ttl-cache.js';

/**
 * Status List キャッシュ TTL の既定上限（秒）。
 *
 * キャッシュが古くなってからも失効済み VC が受理され続ける時間を制限する。
 *
 * 本モジュールの `evaluateCacheFreshness` は評価プリミティブであり、`maxTtlSeconds` で自由に
 * 上書きできる（上限値を強制しない）。SDK 利用者の設定として緩和方向の上書きを**拒否**するのは
 * 配線側（`createStatusListResolver` の `maxTtlSeconds` → `resolveMaxTtlSeconds`）の責務である。
 */
export const DEFAULT_STATUS_CACHE_MAX_TTL_SECONDS = 60;

/** VC のステータス判定結果。 */
export type StatusEntryState = 'valid' | 'revoked' | 'suspended';

/** `evaluateCacheFreshness` の入力。 */
export interface StatusCacheFreshnessInput {
  /** Status List Token を取得した時刻（エポック秒）。 */
  readonly fetchedAtSeconds: number;
  /** 判定する現在時刻（エポック秒）。テストの決定性のため注入する。 */
  readonly nowSeconds: number;
  /** レスポンスの `Cache-Control: max-age`（秒、任意）。 */
  readonly maxAgeSeconds?: number;
  /** Status List Token の `exp`（エポック秒、任意）。 */
  readonly expSeconds?: number;
  /**
   * 呼び出し側が指定する TTL 上限（秒、任意）。既定 `DEFAULT_STATUS_CACHE_MAX_TTL_SECONDS`。
   *
   * `max-age` がこれを超えていても、この値で切り詰める。
   */
  readonly maxTtlSeconds?: number;
}

/** `evaluateCacheFreshness` の結果。 */
export interface StatusCacheFreshness {
  /** キャッシュをそのまま使ってよいか（false なら再取得が必要）。 */
  readonly fresh: boolean;
  /** キャッシュの残り有効秒数（0 以上）。 */
  readonly remainingSeconds: number;
  /** 実際に採用した TTL（秒）。`max-age` と上限のうち小さい方。 */
  readonly effectiveTtlSeconds: number;
  /** キャッシュが失効する時刻（エポック秒）。 */
  readonly expiresAtSeconds: number;
}

/** 値がエポック秒として妥当（有限の非負整数）かを検証する。 */
function assertEpochSeconds(value: number): void {
  if (!Number.isInteger(value) || value < 0) {
    throw new VericertsError(ErrorCodes.VC_SCHEMA_INVALID);
  }
}

/** 値が TTL（秒）として妥当（有限の非負整数）かを検証する。 */
function assertTtlSeconds(value: number): void {
  if (!Number.isInteger(value) || value < 0) {
    throw new VericertsError(ErrorCodes.VC_SCHEMA_INVALID);
  }
}

/**
 * キャッシュ済み Status List Token をまだ使ってよいかを評価する。
 *
 * 採用 TTL は `min(max-age ?? 上限, 上限)`。そこから求めた失効時刻を Token の `exp` でさらに
 * 切り詰める（`exp` を過ぎた Token は TTL が残っていても使わない）。
 *
 * `fetchedAtSeconds` は**自クライアントが取得した時刻**であり、上流キャッシュで既に経過した時間
 * （レスポンスの `Age`）は差し引かない。上流での経過分まで含めた上界が要る場合は `expSeconds` を
 * 渡す。
 *
 * @param input 取得時刻 / 現在時刻 / max-age / exp / TTL 上限。
 * @returns 有効性・残り秒数・採用 TTL・失効時刻。
 * @throws 時刻や TTL が非負整数でない場合（VericertsError、code `3002`）。
 */
export function evaluateCacheFreshness(input: StatusCacheFreshnessInput): StatusCacheFreshness {
  assertEpochSeconds(input.fetchedAtSeconds);
  assertEpochSeconds(input.nowSeconds);
  // 任意オプションは自身のプロパティに限って読む。継承値を拾うと、これらを
  // 指定していない正当な評価でもキャッシュの実効 TTL が広がり、TTL 超過の失効ステータスが
  // 「まだ新鮮」と判定される。継承した `expSeconds` は Token 自体の失効による切り詰めを狂わせる。
  const maxTtl =
    ownProperty<number>(input, 'maxTtlSeconds') ?? DEFAULT_STATUS_CACHE_MAX_TTL_SECONDS;
  assertTtlSeconds(maxTtl);
  const maxAgeSeconds = ownProperty<number>(input, 'maxAgeSeconds');
  if (maxAgeSeconds !== undefined) {
    assertTtlSeconds(maxAgeSeconds);
  }
  const expSeconds = ownProperty<number>(input, 'expSeconds');
  if (expSeconds !== undefined) {
    assertEpochSeconds(expSeconds);
  }

  // 上限で切り詰めた TTL。max-age 未指定なら上限をそのまま使う。
  const effectiveTtlSeconds = Math.min(maxAgeSeconds ?? maxTtl, maxTtl);
  const ttlExpiry = input.fetchedAtSeconds + effectiveTtlSeconds;
  // Token 自体の exp を過ぎたキャッシュは TTL に関わらず使わない。
  const expiresAtSeconds = expSeconds !== undefined ? Math.min(ttlExpiry, expSeconds) : ttlExpiry;
  const remainingSeconds = Math.max(0, expiresAtSeconds - input.nowSeconds);

  return {
    fresh: input.nowSeconds < expiresAtSeconds,
    remainingSeconds,
    effectiveTtlSeconds,
    expiresAtSeconds,
  };
}

/**
 * Status List の評価結果を `valid` / `revoked` / `suspended` に判定する。
 *
 * ビット値が 0 なら有効、0 以外なら解決器の `purpose` に応じて失効 / 一時停止。
 *
 * `StatusListResolver` は公開の DI seam であり、呼び出し側が独自の解決器を差し込める。
 * `StatusCheckResult.valid` は「ビット値が 0」と型契約で定義されているため、
 * `valid !== (value === 0)` はその契約に違反した結果である。本関数は**この不整合を検出した時点で
 * 結果を信頼せず、構造不正として拒否する**方針を採る（`valid=false` を一律で失効扱いにするのでは
 * なく弾く）。壊れた解決器の自己申告に判定を委ねないことで fail-closed を保つ。
 *
 * @param result `StatusListResolver.resolve` の戻り値。
 * @returns 判定結果。
 * @throws `valid` とビット値が矛盾する解決器の結果（VericertsError、code `3002`）。
 */
export function evaluateStatusEntry(result: StatusCheckResult): StatusEntryState {
  const isValidValue = result.value === STATUS_VALUE_VALID;
  if (result.valid !== isValidValue) {
    // 解決器の契約違反。判定材料として信頼できないため構造不正として拒否する（fail-closed）。
    throw new VericertsError(ErrorCodes.VC_SCHEMA_INVALID);
  }
  if (isValidValue) {
    return 'valid';
  }
  return result.purpose === 'suspension' ? 'suspended' : 'revoked';
}

/**
 * ステータス判定結果を検証エラーへ正規化する（fail-closed）。
 *
 * 失効・停止した VC を受理しないよう、Verifier の検証パスから呼ぶ。
 *
 * 判定は `evaluateStatusEntry` に委ねるため、`valid` とビット値が矛盾する解決器の結果も
 * ここで拒否される（素通りさせない）。
 *
 * @param result `StatusListResolver.resolve` の戻り値。
 * @throws 失効時 `VC_REVOKED`（3020）/ 停止時 `VC_SUSPENDED`（3021）。
 * @throws `valid` とビット値が矛盾する場合 `VC_SCHEMA_INVALID`（3002、`evaluateStatusEntry` 由来）。
 */
export function assertStatusValid(result: StatusCheckResult): void {
  const state = evaluateStatusEntry(result);
  if (state === 'revoked') {
    throw new VericertsError(ErrorCodes.VC_REVOKED);
  }
  if (state === 'suspended') {
    throw new VericertsError(ErrorCodes.VC_SUSPENDED);
  }
}
