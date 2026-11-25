/**
 * Replay-Window（クロック誤差許容範囲）の検査。
 *
 * `iat` が「未来すぎる」「古すぎる」場合を検知し、4014 `CLOCK_SKEW_EXCEEDED` として拒否する。
 * Wallet 側は `Date.now()` ベースで動くため、OS 時刻ずれによる失敗はユーザー通知の契機になる。
 */

import { assertFiniteClock } from '../../cache/system-clock.js';
import { CLOCK_SKEW_PROFILE } from '../../credential/time-claims.js';
import { ErrorCodes, VericertsError } from '../../errors.js';
import { ownProperty } from '../../prototype-safety/own-property.js';
import type { NonceFlow } from './types.js';

/**
 * flow ごとの既定 replay window（秒）。
 *
 * `one-time-credential` は VP に載って提示されるため OID4VP と同じ ±30 秒を採る。
 * `dpop` は RFC 9449 §4.3 に従い ±30 秒（`DEFAULT_DPOP_MAX_AGE_SECONDS` と一致）。
 *
 * `oid4vp` は KB-JWT のクロックスキュープロファイル（`CLOCK_SKEW_PROFILE.kbJwt`）から**導出する**。KB-JWT の `iat` は本ウィンドウ（過去・未来の双方）と
 * `verifySdJwt` 側のクランプ（未来方向のみ）で二重に検査されるため、値が食い違うと緩い方が実効窓に
 * なってしまう。リテラルを二重に持つと片方だけ更新される事故が起きるので、単一ソースへ寄せている
 */
export const REPLAY_WINDOW_SECONDS_BY_FLOW: Readonly<Record<NonceFlow, number>> = Object.freeze(
  Object.assign(Object.create(null) as Record<NonceFlow, number>, {
    oid4vci: 30,
    oid4vp: CLOCK_SKEW_PROFILE.kbJwt,
    siopv2: 60,
    'wua-pop': 30,
    'one-time-credential': 30,
    dpop: 30,
  }),
);

/** `assertWithinReplayWindow` のオプション。 */
export interface ReplayWindowOptions {
  /** 現在時刻（UNIX 秒）。既定は `Math.floor(Date.now() / 1000)`。 */
  readonly nowSeconds?: number;
  /** 許容ウィンドウ（秒）。既定は flow によって決まる。 */
  readonly windowSeconds?: number;
}

/**
 * `iat` が replay window 内にあるか検査する。
 *
 * 未来方向・過去方向の双方を同じウィンドウで判定する。
 *
 * @param iatSeconds 検査対象の `iat`（UNIX 秒）。
 * @param flow 対象フロー。既定ウィンドウの選択に使う。
 * @param opts 現在時刻とウィンドウの上書き。
 * @throws `CLOCK_SKEW_OPTION_INVALID`（4015）`nowSeconds` が有限数でない場合（NaN は窓検査を素通りするため）。
 * @throws `CLOCK_SKEW_EXCEEDED`（4014）`iat` が数値でない、またはウィンドウ外の場合。
 */
export function assertWithinReplayWindow(
  iatSeconds: unknown,
  flow: NonceFlow,
  opts: ReplayWindowOptions = {},
): asserts iatSeconds is number {
  if (typeof iatSeconds !== 'number' || !Number.isFinite(iatSeconds)) {
    throw new VericertsError(ErrorCodes.CLOCK_SKEW_EXCEEDED);
  }
  // 任意プロパティは自身のプロパティに限って読む。継承した `windowSeconds`
  // （例 `Infinity`）は KB-JWT / VP のリプレイ窓を丸ごと無効化し、継承した `nowSeconds` は
  // 攻撃者が選んだ「現在時刻」で `iat` を評価させる。
  // `nowSeconds` が NaN だと `Math.abs(now - iat) > window` が常に false になり窓検査が全スキップされる
  // （fail-open）。非有限な現在時刻は 4015 で拒否する。
  const now = assertFiniteClock(
    ownProperty<number>(opts, 'nowSeconds') ?? Math.floor(Date.now() / 1000),
  );
  const window = ownProperty<number>(opts, 'windowSeconds') ?? REPLAY_WINDOW_SECONDS_BY_FLOW[flow];
  // 未知 flow（型外の呼び出し）では既定窓が引けず `window` が undefined になる。
  // `Math.abs(...) > undefined` は NaN 比較で常に false なので、そのまま比較すると
  // **リプレイ窓の検査が黙って全スキップされる**（fail-open）。`REPLAY_WINDOW_SECONDS_BY_FLOW`
  // は `Object.create(null)` 由来でプロトタイプ経由のフォールバックも無いため、ここで
  // 明示的に fail-closed へ倒す。有限の非負数でない窓もすべて拒否する。
  if (typeof window !== 'number' || !Number.isFinite(window) || window < 0) {
    throw new VericertsError(ErrorCodes.CLOCK_SKEW_EXCEEDED);
  }
  if (Math.abs(now - iatSeconds) > window) {
    throw new VericertsError(ErrorCodes.CLOCK_SKEW_EXCEEDED);
  }
}
