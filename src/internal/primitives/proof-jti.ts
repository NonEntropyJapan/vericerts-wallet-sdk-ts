/**
 * 署名側（WUA-PoP / DPoP proof 生成）が載せる JWT `jti` の入口検証。
 *
 * 仕様は `jti` を UUIDv4 必須・32〜36 文字とし、不適合を `4013 NONCE_MALFORMED` とする。
 * 32 文字はハイフンなし、36 文字は正準形（`8-4-4-4-12`）の UUID に当たり、その間の長さは
 * UUID として成立しない。version nibble（`4`）と variant nibble（`8|9|a|b`）まで検査するのは、
 * nil UUID（エントロピー 0）と UUIDv1（タイムスタンプ + MAC 由来）を通さないため。
 *
 * 呼び出し側が渡した値だけを検査する。省略（`undefined`）時は CSPRNG 由来の
 * `crypto.randomUUID()`（UUIDv4）を生成する。
 */

import { ErrorCodes, VericertsError } from '../errors.js';

const UUID_V4_HYPHENATED =
  /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$/;

const UUID_V4_COMPACT = /^[0-9a-fA-F]{12}4[0-9a-fA-F]{3}[89abAB][0-9a-fA-F]{3}[0-9a-fA-F]{12}$/;

/**
 * 署名する `jti` を決める。
 *
 * @param supplied 呼び出し側が指定した `jti`（自身のプロパティとして読んだ値）。`undefined` は未指定。
 * @returns 検査済みの `supplied`、未指定なら新規 UUIDv4。
 * @throws `NONCE_MALFORMED`（4013）`supplied` が UUIDv4 の 32 文字（ハイフンなし）/ 36 文字（正準形）でない場合。
 *         空文字・非文字列（`null` / 数値）・nil UUID・UUIDv1・長さ違いを含む。メッセージに値を含めない。
 */
export function resolveProofJti(supplied: unknown): string {
  if (supplied === undefined) {
    return crypto.randomUUID();
  }
  if (typeof supplied !== 'string') {
    throw new VericertsError(ErrorCodes.NONCE_MALFORMED);
  }
  if (!UUID_V4_HYPHENATED.test(supplied) && !UUID_V4_COMPACT.test(supplied)) {
    throw new VericertsError(ErrorCodes.NONCE_MALFORMED);
  }
  return supplied;
}
