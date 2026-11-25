/**
 * KB-JWT（Key Binding JWT）の検証（`verifySdJwt` から切り出し）。
 *
 * `cnf` 鍵での署名検証と `typ` / `aud` / `nonce` / `sd_hash` の整合、および `iat` の時刻評価を
 * 担う。`verify.ts` の行数上限を圧迫せずに時刻評価の 2 系統（4014 と 3012）の根拠を残すため
 * 独立モジュールにしている。
 *
 * 鍵束縛を**要求**する呼び出し（`requireKeyBinding: true`）に `audience` / `nonce` の期待値が
 * 揃っているかの事前検査（`assertBindingExpectationsPresent`）も本モジュールが担う。
 */

import { assertFiniteClock } from '../../cache/system-clock.js';
import { ErrorCodes, VericertsError } from '../../errors.js';
import { isNonEmptyString } from '../../prototype-safety/non-empty-string.js';
import { ownProperty } from '../../prototype-safety/own-property.js';
import { timingSafeEqualString } from '../../timing-safe.js';
import type { CredentialAlg } from '../vc/jws.js';
import {
  decodeCompactJwsOrThrow,
  SUPPORTED_CREDENTIAL_ALGS,
  verifyWithJwkOrFalse,
} from '../vc/jws.js';
import { KB_JWT_TYP } from './key-binding.js';
import type { ConfirmationClaim } from './sdjwt.js';
import type { VerifySdJwtOptions } from './verify.js';

/**
 * KB-JWT を検証する（cnf 鍵で署名検証 + typ / aud / nonce / sd_hash 整合）。不一致は 3012。
 * KB-JWT ヘッダの alg と `cnf.jwk` の kty / crv が食い違う場合も署名検証不成立として 3012 に揃える。
 *
 * 時刻評価は 2 種類あり、コードが異なる:
 * - 未来 `iat`（`iat > now + kbSkewSeconds`）は `CLOCK_SKEW_EXCEEDED`（4014）。`maxAgeSeconds` の
 *   指定有無に関わらず、KB-JWT を検証する限り常に評価する。
 * - `maxAgeSeconds` 指定時の鮮度（`iat` 欠落・非有限・`now - iat > maxAgeSeconds`）は
 *   `HOLDER_BIND_MISMATCH`（3012）。`maxAgeSeconds` 未指定なら `iat` の鮮度は評価しない。
 * - `nowSeconds` が有限数でない、または `maxAgeSeconds` が有限数でない場合は、いずれの比較も
 *   常に `false` になり未来 `iat`・古い KB-JWT（リプレイ）を素通しするため `4015` で拒否する（fail-closed）。
 *
 * @param kbSkewSeconds KB-JWT 用にクランプ済みのスキュー秒数（`verifySdJwt` が算出。最大 30s）。
 */
export function assertKeyBinding(
  keyBinding: string,
  cnf: ConfirmationClaim | undefined,
  presentedSdHash: string,
  opts: VerifySdJwtOptions,
  kbSkewSeconds: number,
): void {
  if (cnf === undefined) {
    // cnf が無ければ KB-JWT を信頼検証できない。
    throw new VericertsError(ErrorCodes.HOLDER_BIND_MISMATCH);
  }
  // KB-JWT の構造不正も 2001 を漏らさず KB 経路の失敗面（3012）へ正規化する。
  const decoded = decodeCompactJwsOrThrow(keyBinding, ErrorCodes.HOLDER_BIND_MISMATCH);
  // ヘッダ・payload は `decodeCompactJwsOrThrow` → `identity/jwt/jwt-codec.ts` の `parseJson`
  // → `parse-json.ts` の `parseJsonWithoutPrototype` を通るため **`null` プロトタイプ**である。own 限定で読むのは
  // その手法と**重畳する多層防御**であり、加えて本関数は `opts` 側を own 限定で読んでいるので、
  // JWS 側だけ鎖読みのまま残すと同一関数内で読み方が非対称になる。
  // 鎖読みへ戻すと、パース境界を通らない値の流入時に次の破れが復活する。`typ` / `alg` を持たない
  // KB-JWT で汚染値を拾うと、`Object.prototype.typ = 'kb+jwt'` は本来 3012 で閉じる型混同を
  // 素通りさせ、`Object.prototype.alg` は署名検証をその alg で続行させる。
  if (ownProperty<unknown>(decoded.header, 'typ') !== KB_JWT_TYP) {
    throw new VericertsError(ErrorCodes.HOLDER_BIND_MISMATCH);
  }
  const alg = ownProperty<unknown>(decoded.header, 'alg');
  if (typeof alg !== 'string' || !SUPPORTED_CREDENTIAL_ALGS.has(alg)) {
    throw new VericertsError(ErrorCodes.HOLDER_BIND_MISMATCH);
  }
  if (!verifyWithJwkOrFalse(alg as CredentialAlg, decoded, cnf.jwk)) {
    throw new VericertsError(ErrorCodes.HOLDER_BIND_MISMATCH);
  }
  const { payload } = decoded;
  // `aud` / `nonce` は攻撃者が総当たりし得る秘匿値なので定数時間で比較する。型不一致は即座に不一致として扱う。
  // 呼び出し元（`verifySdJwt`）が own 化しているのと読み方を揃える。鎖読みだと
  // aud / nonce 検査を意図的に省略した提示に汚染値との照合が強制され、全 KB-JWT が 3012 に落ちる。
  const expectedAudience = ownProperty<string>(opts, 'audience');
  const expectedNonce = ownProperty<string>(opts, 'nonce');
  // 期待値が `undefined` の項目は照合しない。これは `requireKeyBinding` を指定しない従来経路
  // （KB-JWT が同梱されていれば検証するが「この提示宛か」までは要求しない）のための後方互換で
  // あり、`verifySdJwt` 経由なら `requireKeyBinding: true` の呼び出しは
  // `assertBindingExpectationsPresent` が期待値の欠落を先に 3012 で弾くため、ここへ `undefined`
  // が届くことはない。本関数を直接呼ぶ場合はその前提が無いので、鍵束縛を要求する
  // 文脈では呼び出し側が同ガードを併用すること。
  // @see assertBindingExpectationsPresent
  // `aud` / `nonce` も own 限定で読む（`sd_hash` / `iat` と読み方を揃える）。
  // 鎖読みだと、これらを**持たない** KB-JWT で `Object.prototype.aud` / `.nonce` の汚染値が
  // 「KB-JWT に入っていた値」として定数時間比較に掛かる。攻撃者が期待値を推測できる状況
  // （aud は Verifier の client_id で公開値）では、`aud` / `nonce` を欠く KB-JWT が
  // Holder Binding 検査を通過し得る。存在しないクレームは undefined のまま不一致で拒否させる。
  if (expectedAudience !== undefined) {
    const aud = ownProperty<unknown>(payload, 'aud');
    if (typeof aud !== 'string' || !timingSafeEqualString(aud, expectedAudience)) {
      throw new VericertsError(ErrorCodes.HOLDER_BIND_MISMATCH);
    }
  }
  if (expectedNonce !== undefined) {
    const nonce = ownProperty<unknown>(payload, 'nonce');
    if (typeof nonce !== 'string' || !timingSafeEqualString(nonce, expectedNonce)) {
      throw new VericertsError(ErrorCodes.HOLDER_BIND_MISMATCH);
    }
  }
  // payload は署名済みだが、`sd_hash` / `iat` を**持たない** KB-JWT では鎖読みが
  // `Object.prototype` の汚染値を拾う（own な値があれば shadow するので到達性は低いが、
  // 欠落時のガードを素通りさせないため own 限定で読む）。
  if (ownProperty<unknown>(payload, 'sd_hash') !== presentedSdHash) {
    throw new VericertsError(ErrorCodes.HOLDER_BIND_MISMATCH);
  }
  // 任意オプションは自身のプロパティに限って読む。継承した `nowSeconds` は
  // KB-JWT の `iat` を攻撃者が選んだ「現在時刻」で評価させ、古い KB-JWT のリプレイを通す。
  const now = assertFiniteClock(
    ownProperty<number>(opts, 'nowSeconds') ?? Math.floor(Date.now() / 1000),
  );
  const maxAgeSeconds = ownProperty<number>(opts, 'maxAgeSeconds');
  if (maxAgeSeconds !== undefined) {
    assertFiniteClock(maxAgeSeconds);
  }
  const iat = ownProperty<unknown>(payload, 'iat');
  // 未来 iat（スキュー超過）は maxAgeSeconds の指定有無に関わらず常に拒否する（時計進み・リプレイ試行）。
  if (typeof iat === 'number' && Number.isFinite(iat) && iat > now + kbSkewSeconds) {
    throw new VericertsError(ErrorCodes.CLOCK_SKEW_EXCEEDED);
  }
  if (maxAgeSeconds !== undefined) {
    // iat が無い / 非有限 / 古すぎる KB-JWT は鮮度要件を満たさないとして拒否する。
    if (typeof iat !== 'number' || !Number.isFinite(iat)) {
      throw new VericertsError(ErrorCodes.HOLDER_BIND_MISMATCH);
    }
    if (now - iat > maxAgeSeconds) {
      throw new VericertsError(ErrorCodes.HOLDER_BIND_MISMATCH);
    }
  }
}

/**
 * `requireKeyBinding: true` の呼び出しに `audience` / `nonce` の期待値が揃っているか検査する。
 *
 * `assertKeyBinding` は期待値が `undefined` の項目の照合をスキップする。そのため鍵束縛を
 * **要求**しているのに期待値が無いと、KB-JWT について確認されるのは `typ` / `alg` / `cnf` 鍵に
 * よる署名（＝ 鍵の保持）と `sd_hash` / `iat` だけになり、**「この提示宛か」が一切検査されない**。
 * `aud` が別 Verifier・`nonce` が別セッションの KB-JWT を付けた提示が受理されるため、判定不能な
 * 入力は照合をスキップせず fail-closed で拒否する。
 *
 * 空文字・非文字列は「指定なし」と同じ扱いにする。空文字を許すと、`aud` / `nonce` が空文字の
 * KB-JWT との一致で必須化を迂回できてしまうため。
 *
 * オプションは own 限定で読む。継承した `audience` / `nonce` を必須充足と見なすと、
 * `Object.prototype` 汚染ひとつで本ガードが無効化される。
 *
 * @throws 3012 `requireKeyBinding: true` で `audience` / `nonce` のいずれかが欠けている場合。
 */
export function assertBindingExpectationsPresent(opts: VerifySdJwtOptions): void {
  if (ownProperty<unknown>(opts, 'requireKeyBinding') !== true) {
    return;
  }
  if (
    !isNonEmptyString(ownProperty<unknown>(opts, 'audience')) ||
    !isNonEmptyString(ownProperty<unknown>(opts, 'nonce'))
  ) {
    throw new VericertsError(ErrorCodes.HOLDER_BIND_MISMATCH);
  }
}
