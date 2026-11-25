/**
 * nonce の生成とフォーマット / エントロピー検査。
 *
 * 生成には CSPRNG（`crypto.getRandomValues`）を使う。文字列だけでは乱数源を確かめられないため、
 * 受信時には文字種と長さを検査する。
 */

import { base64urlnopad } from '@scure/base';
import { ErrorCodes, VericertsError } from '../../errors.js';

/** nonce 生成時の最小エントロピー（bit）。 */
export const MIN_NONCE_ENTROPY_BITS = 128;

/**
 * base64url（パディング無し）最小長。
 * 128 bit = 16 byte を base64url 化すると 22 文字になる（`ceil(16 * 8 / 6)`）。
 */
export const MIN_NONCE_LENGTH = 22;

/** base64url（パディング無し）の文字種。 */
const BASE64URL_PATTERN = /^[A-Za-z0-9_-]+$/;

/**
 * UUIDv4（RFC 4122 §4.4）形式。`jti` もこの形式を取り得る。
 *
 * version nibble（`4`）と variant nibble（`8|9|a|b`）まで検査する。桁数と文字種だけを見る
 * 緩い形式検査では、nil UUID（`00000000-0000-0000-0000-000000000000`、エントロピー 0）や
 * タイムスタンプを含む UUIDv1 も通ってしまう。
 * UUIDv4 の乱数部は 122 bit だが、`jti` の形式として受理する。
 */
const UUID_V4_PATTERN =
  /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$/;

/**
 * UUID の骨格（桁数とハイフン位置）。version / variant は問わない。
 *
 * base64url の文字種は `-` を含むため、UUID 形状の文字列は 22 文字以上という理由だけで
 * `BASE64URL_PATTERN` も通ってしまう。それでは version / variant を厳しくしても
 * base64url 経路から nil UUID / UUIDv1 が素通りするので、UUID 形状なら UUIDv4 判定だけで
 * 決着させる（この形状の文字列を CSPRNG が偶然生成する確率は無視できる）。
 */
const UUID_SHAPE_PATTERN =
  /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;

/**
 * CSPRNG で nonce を生成する。
 *
 * `crypto.getRandomValues` は browser / Node.js / Bun のいずれでも利用できる。
 *
 * @param byteLength 生成するバイト数。既定 16（= 128 bit）。
 * @returns base64url（パディング無し）エンコードされた nonce。
 */
export function generateNonce(byteLength: 16 | 32 = 16): string {
  const buf = new Uint8Array(byteLength);
  crypto.getRandomValues(buf);
  return base64urlnopad.encode(buf);
}

/**
 * nonce が受理できる形式かを判定する。
 *
 * @param nonce 判定対象。
 * @returns base64url 22 文字以上、または UUIDv4 形式なら `true`。
 */
export function isWellFormedNonce(nonce: unknown): nonce is string {
  if (typeof nonce !== 'string' || nonce.length === 0) {
    return false;
  }
  if (UUID_SHAPE_PATTERN.test(nonce)) {
    return UUID_V4_PATTERN.test(nonce);
  }
  return nonce.length >= MIN_NONCE_LENGTH && BASE64URL_PATTERN.test(nonce);
}

/**
 * nonce のフォーマット / エントロピーを検査し、不正なら 4013 を投げる。
 *
 * 値からは生成器（CSPRNG か否か）を検証できないため、文字種と長さで判定する。
 * 長さ不足は 128 bit 未満のエントロピーを意味するため「エントロピー不足」として同じコードで扱う。
 *
 * @param nonce 検査対象。
 * @throws `NONCE_MALFORMED`（4013）フォーマット不正・エントロピー不足の場合。
 */
export function assertWellFormedNonce(nonce: unknown): asserts nonce is string {
  if (!isWellFormedNonce(nonce)) {
    throw new VericertsError(ErrorCodes.NONCE_MALFORMED);
  }
}
