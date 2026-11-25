/**
 * did:ebsi の DID 形式・ローカル生成・鍵名。
 *
 * ```text
 * did:ebsi:z<base58btc( [version byte = 1] || [16 バイトの乱数] )>
 * ```
 *
 * 受理するのは network を省略した形（EBSI ブロックチェーン）とバージョンバイト `1`（法人）だけで、
 * それ以外は `2001`（`context.reason: "ebsi_unsupported_form"`）で拒否する。DID の生成はローカルのみで、
 * Registry への登録は呼び出し側の責務。
 */

import { sha256 } from '@noble/hashes/sha2.js';
import { base64urlnopad } from '@scure/base';
import { ErrorCodes, VericertsError } from '../../errors.js';
import { ownProperty } from '../../prototype-safety/own-property.js';
import type { PublicKeyJwk } from '../did.js';
import { multibaseBase58Decode, multibaseBase58Encode } from '../multibase.js';

/** DID の接頭辞。 */
const DID_EBSI_PREFIX = 'did:ebsi:';

/** 法人（Legal Entity）のバージョンバイト。 */
const LEGAL_ENTITY_VERSION = 1;

/** 識別子本体の乱数部のバイト数。 */
const RANDOM_BYTES = 16;

/** 識別子（バージョンバイト + 乱数）の長さ。 */
const IDENTIFIER_BYTES = 1 + RANDOM_BYTES;

/** 識別子（`z` + base58btc）の最大文字数。17 バイトの base58btc は 24 文字以内に収まる。 */
const MAX_IDENTIFIER_CHARS = 32;

/** 座標 `x` / `y` の長さ（P-256 / secp256k1 とも 32 バイト）。 */
const COORDINATE_BYTES = 32;

function invalidDid(reason: string): VericertsError {
  return new VericertsError(ErrorCodes.INVALID_DID, { context: { reason } });
}

/**
 * did:ebsi を検証し、識別子（`z...`）を返す。
 *
 * @throws network 付き・バージョンバイトが `1` 以外（code `2001`、`ebsi_unsupported_form`）、
 *   形式不正（code `2001`、`ebsi_invalid_identifier`）。
 */
export function parseDidEbsi(did: string): { readonly identifier: string } {
  if (!did.startsWith(DID_EBSI_PREFIX)) {
    throw invalidDid('ebsi_invalid_identifier');
  }
  const identifier = did.slice(DID_EBSI_PREFIX.length);
  if (identifier.includes(':')) {
    // `did:ebsi:<network>:<msi>` は別 Registry を指す宛先で、検証手段がない。
    throw invalidDid('ebsi_unsupported_form');
  }
  if (identifier.length > MAX_IDENTIFIER_CHARS) {
    throw invalidDid('ebsi_invalid_identifier');
  }
  let bytes: Uint8Array;
  try {
    bytes = multibaseBase58Decode(identifier, MAX_IDENTIFIER_CHARS);
  } catch {
    throw invalidDid('ebsi_invalid_identifier');
  }
  if (bytes.length !== IDENTIFIER_BYTES) {
    throw invalidDid('ebsi_invalid_identifier');
  }
  if (bytes[0] !== LEGAL_ENTITY_VERSION) {
    throw invalidDid('ebsi_unsupported_form');
  }
  return { identifier };
}

/**
 * did:ebsi を生成する（version 1 + 乱数 16 バイトを multibase base58btc で符号化。登録はしない）。
 *
 * @param options.randomBytes 乱数源（省略時は `crypto.getRandomValues`。テスト用に差し替える）。
 */
export function generateDidEbsi(options?: { randomBytes?: (n: number) => Uint8Array }): {
  did: string;
} {
  const randomBytes =
    (options === undefined
      ? undefined
      : ownProperty<(n: number) => Uint8Array>(options, 'randomBytes')) ??
    ((n: number) => crypto.getRandomValues(new Uint8Array(n)));
  const random = randomBytes(RANDOM_BYTES);
  if (random.length !== RANDOM_BYTES) {
    throw invalidDid('ebsi_invalid_random');
  }
  const bytes = new Uint8Array(IDENTIFIER_BYTES);
  bytes[0] = LEGAL_ENTITY_VERSION;
  bytes.set(random, 1);
  return { did: `${DID_EBSI_PREFIX}${multibaseBase58Encode(bytes)}` };
}

/**
 * 検証メソッドのキー名の推奨値（JWK Thumbprint、RFC 7638）を返す。
 *
 * EBSI は同じ鍵を 1 度しか登録できず、キー名は後から変更できない。対象は `EC` の
 * `P-256` / `secp256k1` だけで、それ以外・座標の不正は `2010`（`ebsi_key_unsupported`）。
 */
export function ebsiKeyName(publicKeyJwk: PublicKeyJwk): string {
  const kty = ownProperty<unknown>(publicKeyJwk, 'kty');
  const crv = ownProperty<unknown>(publicKeyJwk, 'crv');
  const x = ownProperty<unknown>(publicKeyJwk, 'x');
  const y = ownProperty<unknown>(publicKeyJwk, 'y');
  if (!isEbsiSupportedKey(publicKeyJwk) || !isCoordinate(x) || !isCoordinate(y)) {
    throw new VericertsError(ErrorCodes.DID_DOC_INVALID, {
      context: { reason: 'ebsi_key_unsupported' },
    });
  }
  // RFC 7638 §3.2: 必須メンバを辞書順（crv, kty, x, y）・空白なしで並べる。順序を変えないこと。
  const canonical = JSON.stringify({ crv, kty, x, y });
  return base64urlnopad.encode(sha256(new TextEncoder().encode(canonical)));
}

/** base64url（パディングなし）で 32 バイトに復号できる座標か。 */
function isCoordinate(value: unknown): value is string {
  if (typeof value !== 'string') {
    return false;
  }
  try {
    return base64urlnopad.decode(value).length === COORDINATE_BYTES;
  } catch {
    return false;
  }
}

/**
 * `publicKeyJwk` が EBSI の対象鍵（`EC` の `P-256` / `secp256k1`）かを返す。解決結果の検査用。
 */
export function isEbsiSupportedKey(publicKeyJwk: unknown): boolean {
  if (typeof publicKeyJwk !== 'object' || publicKeyJwk === null) {
    return false;
  }
  const crv = ownProperty<unknown>(publicKeyJwk, 'crv');
  return (
    ownProperty<unknown>(publicKeyJwk, 'kty') === 'EC' && (crv === 'P-256' || crv === 'secp256k1')
  );
}
