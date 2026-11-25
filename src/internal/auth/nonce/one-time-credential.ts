/**
 * 一回限り使用 VC（Human Approval VC 等）の `jti` 消費。
 *
 * 保持期間は VP ではなく **VC の `exp` まで**とする。VC は VP より長寿命なため、VP 側の
 * 保持期間（VP の `exp` + 30 秒）で切ると、同じ VC を別の VP に載せ替えて再利用できてしまう。
 */

import { ErrorCodes, VericertsError } from '../../errors.js';
import { ownProperty } from '../../prototype-safety/own-property.js';
import type { NonceContext, NonceStore } from './types.js';

/** VP nonce に加算する猶予（ms）。「VP の有効期限 + 30 秒」まで保持する。 */
export const VP_NONCE_RETENTION_GRACE_MS = 30_000;

/**
 * VP 用 nonce の保持期間を算出する（VP の有効期限 + 30 秒）。
 *
 * @param vpExpiresAtMs VP の有効期限（UNIX ms）。
 * @param nowMs 現在時刻（UNIX ms）。
 * @returns 保持期間（ms）。期限超過が猶予（30 秒）以内なら正、それを超えると 0 以下になる（クランプしない）。
 */
export function vpNonceRetentionMs(vpExpiresAtMs: number, nowMs: number): number {
  return vpExpiresAtMs - nowMs + VP_NONCE_RETENTION_GRACE_MS;
}

/** `consumeOneTimeCredential` の入力。 */
export interface ConsumeOneTimeCredentialOptions {
  /** 一回限り使用 VC の `jti`。 */
  readonly jti: string;
  /** VC の発行者（コンテキスト分離のキー）。 */
  readonly issuer: string;
  /** VC の `exp`（UNIX 秒）。この時刻まで `jti` を保持する。 */
  readonly expSeconds: number;
  /** 現在時刻（UNIX ms）。テスト注入用。既定は `Date.now()`。 */
  readonly nowMs?: number;
}

/**
 * 一回限り使用 VC の `jti` を消費する。
 *
 * 2 回目の呼び出しは 4010 `REPLAY_DETECTED` になる。VC が既に失効している場合は
 * 4011 `NONCE_EXPIRED` を投げる（保持期間が非正になるため記録する意味がない）。
 *
 * @param store 消費記録を保持する `NonceStore`。
 * @param opts `jti` / 発行者 / VC の `exp`。
 * @throws 4010 消費済み / 4011 VC 失効済み / 4013 `jti` の形式不正。
 */
export async function consumeOneTimeCredential(
  store: NonceStore,
  opts: ConsumeOneTimeCredentialOptions,
): Promise<void> {
  // テスト注入用の任意プロパティは自身のプロパティに限って読む。継承した `nowMs`
  // は保持期間を両方向に歪め、小さい値なら失効済み VC を消費記録に乗せ（fail-open）、大きい値なら
  // 有効な VC を常に 4011 で拒否する。
  const now = ownProperty<number>(opts, 'nowMs') ?? Date.now();
  const retentionMs = opts.expSeconds * 1000 - now;
  // NaN（`nowMs` / `expSeconds` の非有限値）は `<= 0` が false になり失効済み VC を消費記録へ乗せるため、
  // 「正の有限」でなければ失効扱いにする（fail-closed）。
  if (!(retentionMs > 0) || !Number.isFinite(retentionMs)) {
    throw new VericertsError(ErrorCodes.NONCE_EXPIRED);
  }
  const ctx: NonceContext = { flow: 'one-time-credential', issuer: opts.issuer };
  await store.checkAndUse(opts.jti, ctx, { ttlMs: retentionMs });
}
