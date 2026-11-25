/**
 * SLIP-0039 のマスターシークレット暗号化（4-round Feistel network、spec §Encryption of the
 * master secret）。ラウンド関数は PBKDF2-HMAC-SHA256（`@noble/hashes`、isomorphic）。
 *
 * 本 SDK の公開 API（createShamirShares / recoverFromShamirShares）はパスフレーズを扱わない
 * （常に空文字列）。パスフレーズ引数を残しているのは SLIP-0039 公式テストベクタ（passphrase
 * 付き）でこのモジュール単体を検証できるようにするため。
 */

import { pbkdf2 } from '@noble/hashes/pbkdf2.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { concatBytes } from '../../asset/bytes.js';

const BASE_ITERATION_COUNT = 10000;
const ROUND_COUNT = 4;
const CUSTOMIZATION_STRING_ORIG = new TextEncoder().encode('shamir');

function xor(a: Uint8Array, b: Uint8Array): Uint8Array<ArrayBuffer> {
  if (a.length !== b.length) {
    throw new Error('SLIP-0039: xor operands length mismatch');
  }
  const result = new Uint8Array(a.length);
  for (let i = 0; i < a.length; i++) {
    result[i] = (a[i] ?? 0) ^ (b[i] ?? 0);
  }
  return result;
}

function roundFunction(
  round: number,
  passphrase: Uint8Array,
  iterationExponent: number,
  salt: Uint8Array,
  r: Uint8Array,
): Uint8Array {
  const password = concatBytes(new Uint8Array([round]), passphrase);
  const pbkdfSalt = concatBytes(salt, r);
  const iterations = (BASE_ITERATION_COUNT << iterationExponent) / ROUND_COUNT;
  return pbkdf2(sha256, password, pbkdfSalt, { c: iterations, dkLen: r.length });
}

/**
 * `id` を暗号化のソルトに含めるか。拡張可能バックアップ（`extendable`）では含めない
 * （spec §10「Extendable backup flag」）。
 */
function getSalt(identifier: number, extendable: boolean): Uint8Array {
  if (extendable) {
    return new Uint8Array(0);
  }
  const identifierBytes = new Uint8Array(2);
  identifierBytes[0] = (identifier >> 8) & 0xff;
  identifierBytes[1] = identifier & 0xff;
  return concatBytes(CUSTOMIZATION_STRING_ORIG, identifierBytes);
}

function feistel(
  data: Uint8Array,
  passphrase: Uint8Array,
  iterationExponent: number,
  identifier: number,
  extendable: boolean,
  rounds: readonly number[],
): Uint8Array {
  const half = data.length / 2;
  let l: Uint8Array<ArrayBufferLike> = data.slice(0, half);
  let r: Uint8Array<ArrayBufferLike> = data.slice(half);
  const salt = getSalt(identifier, extendable);
  for (const round of rounds) {
    const f = roundFunction(round, passphrase, iterationExponent, salt, r);
    const nextR = xor(l, f);
    l = r;
    r = nextR;
  }
  return concatBytes(r, l);
}

/**
 * マスターシークレットを暗号化する（`EMS = R || L`、4-round Feistel）。
 *
 * @param masterSecret 偶数バイト長の平文（SLIP-0039 の制約）。
 */
export function encryptMasterSecret(
  masterSecret: Uint8Array,
  passphrase: Uint8Array,
  iterationExponent: number,
  identifier: number,
  extendable: boolean,
): Uint8Array {
  if (masterSecret.length % 2 !== 0) {
    throw new Error('SLIP-0039: master secret length must be even');
  }
  return feistel(masterSecret, passphrase, iterationExponent, identifier, extendable, [0, 1, 2, 3]);
}

/** 暗号化されたマスターシークレットを復号する（{@link encryptMasterSecret} の逆演算）。 */
export function decryptMasterSecret(
  encryptedMasterSecret: Uint8Array,
  passphrase: Uint8Array,
  iterationExponent: number,
  identifier: number,
  extendable: boolean,
): Uint8Array {
  if (encryptedMasterSecret.length % 2 !== 0) {
    throw new Error('SLIP-0039: encrypted master secret length must be even');
  }
  return feistel(
    encryptedMasterSecret,
    passphrase,
    iterationExponent,
    identifier,
    extendable,
    [3, 2, 1, 0],
  );
}
