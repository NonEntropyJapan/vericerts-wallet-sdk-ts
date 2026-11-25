/**
 * vault / `encrypt` が受理するパスワードの入力検査。
 *
 * 空文字は KDF の入力として成立してしまい（実質無鍵の vault ができる）、非文字列は KDF 側の
 * 例外・暗黙変換に任せると挙動が不定になる。`importRecoveredWallet` の `walletPassword`
 * （欠落・非文字列・空文字を `1031`）と同じ規律を、同じ vault を作る他の入口にも揃える。
 *
 * セキュリティ上の注意: パスワードの値は例外 message / context に含めない。
 */

import { ErrorCodes, VericertsError } from '../../errors.js';
import { ownProperty } from '../../prototype-safety/own-property.js';

/** 空でない文字列か（`unknown` で受けて型違反の JS 呼び出しも弾く）。 */
export function isNonEmptyPassword(password: unknown): password is string {
  return typeof password === 'string' && password.length > 0;
}

/**
 * `importMnemonic` の `options.persistPassword` を own 限定で読み、指定されていれば検査する。
 *
 * 鎖読みでは汚染値が「永続化する」を満たしてしまう。検査は seed の差し替え前に
 * 行うため、不正なパスワードで呼んでも既存のウォレット状態は変わらない。
 *
 * @returns 検査済みの `persistPassword`（未指定なら `undefined`）。
 * @throws 指定されたが空文字・非文字列の場合（VericertsError、code `1031`）。
 */
export function readPersistPassword(options: object | undefined): string | undefined {
  const persistPassword =
    options === undefined ? undefined : ownProperty<unknown>(options, 'persistPassword');
  if (persistPassword === undefined) {
    return undefined;
  }
  if (!isNonEmptyPassword(persistPassword)) {
    throw new VericertsError(ErrorCodes.PIN_POLICY_VIOLATION);
  }
  return persistPassword;
}
