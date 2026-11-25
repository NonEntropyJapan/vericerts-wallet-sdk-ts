/**
 * SLIP-0039 の SplitSecret / RecoverSecret（spec §Sharing a secret）。
 *
 * 閾値 `threshold` 個のシェアから秘密を復元できるように、GF(256) 上の多項式補間
 * （{@link interpolate}）で残りのシェアを計算する。`threshold` が 2 以上の場合は
 * index 254 に HMAC-SHA256 ダイジェストを埋め込み、復元時に改ざん・不整合を検知する
 * （spec §Digest）。乱数は `crypto.getRandomValues`（Web Crypto、isomorphic）を使う。
 */

import { hmac } from '@noble/hashes/hmac.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { interpolate, type RawShare } from './gf256.js';

export type { RawShare } from './gf256.js';

const DIGEST_INDEX = 254;
const SECRET_INDEX = 255;
const DIGEST_LENGTH_BYTES = 4;

function randomBytes(length: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(length));
}

function createDigest(randomPart: Uint8Array, sharedSecret: Uint8Array): Uint8Array {
  return hmac(sha256, randomPart, sharedSecret).slice(0, DIGEST_LENGTH_BYTES);
}

/**
 * 定数時間のバイト列比較。
 *
 * 長さが同じ限り、最初の不一致で打ち切らず全バイトを XOR して畳み込む。ダイジェスト照合は
 * 攻撃者が自分で用意したシェアを照合させる構図なので実害は薄いが、秘密由来の値の比較を
 * 早期 return で書く前例を残さない。
 */
function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) {
    return false;
  }
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= (a[i] ?? 0) ^ (b[i] ?? 0);
  }
  return diff === 0;
}

/**
 * 秘密を `shareCount` 個のシェアに分割する（うち `threshold` 個で復元可能）。
 *
 * @throws `threshold` / `shareCount` の関係が不正な場合（`Error`）。
 */
export function splitSecret(
  threshold: number,
  shareCount: number,
  sharedSecret: Uint8Array,
): RawShare[] {
  if (threshold < 1) {
    throw new Error('SLIP-0039: threshold must be a positive integer');
  }
  if (threshold > shareCount) {
    throw new Error('SLIP-0039: threshold must not exceed shareCount');
  }

  // threshold が 1 の場合はダイジェストを使わず、全シェアが秘密そのものになる。
  if (threshold === 1) {
    return Array.from({ length: shareCount }, (_, i) => ({ x: i, data: sharedSecret }));
  }

  const randomShareCount = threshold - 2;
  const shares: RawShare[] = Array.from({ length: randomShareCount }, (_, i) => ({
    x: i,
    data: randomBytes(sharedSecret.length),
  }));

  const randomPart = randomBytes(sharedSecret.length - DIGEST_LENGTH_BYTES);
  const digest = createDigest(randomPart, sharedSecret);
  const digestValue = new Uint8Array(digest.length + randomPart.length);
  digestValue.set(digest, 0);
  digestValue.set(randomPart, digest.length);

  const baseShares: RawShare[] = [
    ...shares,
    { x: DIGEST_INDEX, data: digestValue },
    { x: SECRET_INDEX, data: sharedSecret },
  ];

  for (let i = randomShareCount; i < shareCount; i++) {
    shares.push({ x: i, data: interpolate(baseShares, i) });
  }

  return shares;
}

/**
 * `threshold` 個以上のシェアから秘密を復元する。
 *
 * @throws ダイジェスト不一致（改ざん・不整合なシェアの組み合わせ）の場合（`Error`）。
 */
export function recoverSecret(threshold: number, shares: readonly RawShare[]): Uint8Array {
  if (threshold === 1) {
    const [first] = shares;
    if (first === undefined) {
      throw new Error('SLIP-0039: no shares provided');
    }
    return first.data;
  }

  const sharedSecret = interpolate(shares, SECRET_INDEX);
  const digestShare = interpolate(shares, DIGEST_INDEX);
  const digest = digestShare.slice(0, DIGEST_LENGTH_BYTES);
  const randomPart = digestShare.slice(DIGEST_LENGTH_BYTES);

  const expectedDigest = createDigest(randomPart, sharedSecret);
  if (!bytesEqual(digest, expectedDigest)) {
    throw new Error('SLIP-0039: invalid digest of the shared secret');
  }

  return sharedSecret;
}
