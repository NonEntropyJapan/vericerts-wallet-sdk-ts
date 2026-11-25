/**
 * VerificationMethod の公開鍵表現（`publicKeyJwk` / `publicKeyMultibase` / `publicKeyHex` / `publicKeyBase58`）から
 * 検証鍵 JWK を取り出す変換レイヤ。
 *
 * `verifier-key.ts` から分離した純粋関数群（1 ファイル 300 行以下のため）。検証鍵の「選択」
 * （どの VerificationMethod を使うか）は `verifier-key.ts` の責務で、本モジュールは選ばれた
 * VerificationMethod の「変換」のみを担う。
 *
 * 対応する鍵タイプ:
 *
 * | kty   | crv                  | 対応 alg  | did:key multicodec      |
 * | ----- | -------------------- | --------- | ----------------------- |
 * | `EC`  | `P-256`              | `ES256`   | `0x1200` → `[0x80,0x24]`|
 * | `EC`  | `secp256k1`          | `ES256K`  | `0xe701` → `[0xe7,0x01]`|
 * | `OKP` | `Ed25519`            | `EdDSA`   | `0xed01` → `[0xed,0x01]`|
 *
 * それ以外（RSA・X25519 等）は未対応とし `UNSUPPORTED_ALGORITHM`（code `1030`）を投げる。
 *
 * レイヤリング: 鍵の低レベル変換は Foundation の `identity/multibase.ts`（multibase decode）を
 * 再利用し、`@noble/curves` で圧縮公開鍵を非圧縮へ展開する。
 *
 * セキュリティ上の注意:
 * - 例外メッセージや `context` に DID 文字列・公開鍵バイトなどの入力データを含めない。
 */

import { p256 } from '@noble/curves/nist.js';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { base58, base64urlnopad } from '@scure/base';
import { ErrorCodes, VericertsError } from '../../errors.js';
import type { PublicKeyJwk, VerificationMethod } from '../../identity/did.js';
import { encodeMulticodecVarint, multibaseBase58Decode } from '../../identity/multibase.js';
import { ownProperty } from '../../prototype-safety/own-property.js';

/** EC 検証鍵抽出の曲線パラメータ（JWK crv と圧縮鍵展開用の曲線実装）。 */
interface EcKeySpec {
  /** JWK `kty` 値。 */
  readonly kty: 'EC';
  /** JWK `crv` 値。 */
  readonly crv: 'P-256' | 'secp256k1';
  /** 圧縮 / 非圧縮公開鍵バイト列を扱う `@noble/curves` の曲線。 */
  readonly curve: typeof secp256k1;
}

/** OKP（Ed25519）検証鍵抽出のパラメータ。EC と異なり曲線点の展開を行わない。 */
interface OkpKeySpec {
  /** JWK `kty` 値。 */
  readonly kty: 'OKP';
  /** JWK `crv` 値。 */
  readonly crv: 'Ed25519';
}

/** 検証鍵の種別ごとのパラメータ（`kty` による判別可能ユニオン）。 */
type KeySpec = EcKeySpec | OkpKeySpec;

/** secp256k1 用パラメータ。 */
const SECP256K1_SPEC: EcKeySpec = { kty: 'EC', crv: 'secp256k1', curve: secp256k1 };
/** P-256 用パラメータ。 */
const P256_SPEC: EcKeySpec = { kty: 'EC', crv: 'P-256', curve: p256 };
/** Ed25519 用パラメータ。 */
const ED25519_SPEC: OkpKeySpec = { kty: 'OKP', crv: 'Ed25519' };

/**
 * did:key の multicodec varint プレフィックス → 検証鍵パラメータの対応表。
 *
 * `encodeMulticodecVarint` で canonical な varint を生成して照合に使う:
 * - secp256k1: `0xe701` → `[0xe7, 0x01]`
 * - P-256: `0x1200` → `[0x80, 0x24]`
 * - Ed25519: `0xed01` → `[0xed, 0x01]`
 */
const MULTICODEC_SPECS: ReadonlyArray<readonly [Uint8Array, KeySpec]> = [
  [encodeMulticodecVarint(0xe7), SECP256K1_SPEC],
  [encodeMulticodecVarint(0x1200), P256_SPEC],
  [encodeMulticodecVarint(0xed), ED25519_SPEC],
];

/** EC 公開鍵 JWK の座標長（P-256 / secp256k1 とも 32 バイト）。 */
const EC_COORDINATE_LENGTH = 32;
/** OKP（Ed25519）公開鍵の長さ（32 バイト）。 */
const OKP_KEY_LENGTH = 32;
/** 非圧縮 EC 公開鍵の SEC1 プレフィックス（`0x04`）。 */
const UNCOMPRESSED_POINT_PREFIX = 0x04;

/** バイト列を base64url（パディングなし）文字列へエンコードする。 */
function toBase64url(bytes: Uint8Array): string {
  return base64urlnopad.encode(bytes);
}

/**
 * SEC1 非圧縮公開鍵（`0x04 || x(32) || y(32)`）を EC 公開鍵 JWK へ変換する。
 *
 * @param uncompressed 65 バイトの非圧縮公開鍵。
 * @param crv JWK `crv` 値。
 * @returns EC 公開鍵 JWK（`kty` / `crv` / `x` / `y`）。
 * @throws バイト列が 65 バイトの非圧縮形式でない場合（VericertsError、code `2010`）。
 */
function uncompressedToJwk(uncompressed: Uint8Array, crv: 'P-256' | 'secp256k1'): PublicKeyJwk {
  if (
    uncompressed.length !== 1 + EC_COORDINATE_LENGTH * 2 ||
    uncompressed[0] !== UNCOMPRESSED_POINT_PREFIX
  ) {
    throw new VericertsError(ErrorCodes.DID_DOC_INVALID);
  }
  return {
    kty: 'EC',
    crv,
    x: toBase64url(uncompressed.subarray(1, 1 + EC_COORDINATE_LENGTH)),
    y: toBase64url(uncompressed.subarray(1 + EC_COORDINATE_LENGTH)),
  };
}

/**
 * 生公開鍵バイト列を検証鍵 JWK へ変換する。
 *
 * EC（`kty: 'EC'`）は `@noble/curves` の `Point.fromBytes` で曲線上の点として復元（不正点は例外）し、
 * `toBytes(false)` で非圧縮 65 バイトへ展開してから `{ kty:'EC', crv, x, y }` を組み立てる。
 * OKP（Ed25519）は曲線点の展開を行わず、32 バイトの生公開鍵をそのまま `x` に載せる。
 *
 * @param raw 生公開鍵（EC は圧縮 33 バイト / 非圧縮 65 バイト、OKP は 32 バイト）。
 * @param spec 検証鍵パラメータ。
 * @returns 公開鍵 JWK。
 * @throws 曲線上の点として復元できない / OKP の長さが 32 バイトでない場合
 *         （VericertsError、code `2010`）。
 */
function rawPublicKeyToJwk(raw: Uint8Array, spec: KeySpec): PublicKeyJwk {
  if (spec.kty === 'OKP') {
    if (raw.length !== OKP_KEY_LENGTH) {
      throw new VericertsError(ErrorCodes.DID_DOC_INVALID);
    }
    return { kty: 'OKP', crv: spec.crv, x: toBase64url(raw) };
  }
  let uncompressed: Uint8Array;
  try {
    uncompressed = spec.curve.Point.fromBytes(raw).toBytes(false);
  } catch {
    // @noble 由来の例外は入力を含み得るため cause を渡さず正規化する。
    throw new VericertsError(ErrorCodes.DID_DOC_INVALID);
  }
  return uncompressedToJwk(uncompressed, spec.crv);
}

/**
 * `publicKeyMultibase`（did:key 等）から検証鍵 JWK を取り出す。
 *
 * base58btc を decode し、先頭の multicodec varint で secp256k1 / P-256 / Ed25519 を判定する。
 * それ以外（X25519・RSA 等）の multicodec は未対応として弾く。
 *
 * @param multibase `z` + base58btc 文字列。
 * @returns 公開鍵 JWK（EC または OKP）。
 * @throws 未対応の multicodec の場合（VericertsError、code `1030`）、
 *         multibase / 公開鍵が不正な場合（code `2001` / `2010`）。
 */
function multibaseToJwk(multibase: string): PublicKeyJwk {
  const decoded = multibaseBase58Decode(multibase);
  for (const [prefix, spec] of MULTICODEC_SPECS) {
    if (hasPrefix(decoded, prefix)) {
      return rawPublicKeyToJwk(decoded.subarray(prefix.length), spec);
    }
  }
  // 既知の対応 multicodec（secp256k1 / P-256 / Ed25519）に一致しない。
  throw new VericertsError(ErrorCodes.UNSUPPORTED_ALGORITHM);
}

/** `bytes` の先頭が `prefix` と完全一致するか。 */
function hasPrefix(bytes: Uint8Array, prefix: Uint8Array): boolean {
  if (bytes.length < prefix.length) {
    return false;
  }
  for (let i = 0; i < prefix.length; i++) {
    if (bytes[i] !== prefix[i]) {
      return false;
    }
  }
  return true;
}

/**
 * `publicKeyHex`（did:ethr の Secp256k1 検証鍵）から検証鍵 JWK を取り出す。
 *
 * did:ethr の `EcdsaSecp256k1VerificationKey2019` は secp256k1 公開鍵を hex で持つため、
 * `0x` プレフィックス（任意）を除去し、圧縮 / 非圧縮いずれの hex も曲線上で展開して JWK 化する。
 *
 * @param hex hex 公開鍵（`0x` 付き / なし、圧縮 33 バイト / 非圧縮 65 バイト相当）。
 * @returns secp256k1 の EC 公開鍵 JWK。
 * @throws hex が不正 / 曲線上の点でない場合（VericertsError、code `2010`）。
 */
function hexToJwk(hex: string): PublicKeyJwk {
  const body = hex.startsWith('0x') || hex.startsWith('0X') ? hex.slice(2) : hex;
  if (body.length === 0 || body.length % 2 !== 0 || !/^[0-9a-fA-F]+$/.test(body)) {
    throw new VericertsError(ErrorCodes.DID_DOC_INVALID);
  }
  const bytes = new Uint8Array(body.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = Number.parseInt(body.slice(i * 2, i * 2 + 2), 16);
  }
  return rawPublicKeyToJwk(bytes, SECP256K1_SPEC);
}

/**
 * JWK が対応 alg（`ES256` / `ES256K` / `EdDSA`）で検証できる公開鍵か検証し、そのまま返す。
 *
 * `kty` ごとに要求する形状が異なる（RFC 7518 / RFC 8037）:
 * - `EC`: `crv` が `P-256` / `secp256k1` で、`x` と `y` の双方が必要。
 * - `OKP`: `crv` が `Ed25519` で、`x` のみ（`y` は持たない）。
 *
 * それ以外の `kty` / `crv`（RSA・X25519 等）は未対応として `UNSUPPORTED_ALGORITHM`（1030）。
 */
function assertVerifiableJwk(jwk: PublicKeyJwk): PublicKeyJwk {
  // JWK のメンバも own 限定で読む（汚染された `Object.prototype.x` / `y` で欠落メンバを補わせない）。
  const kty = ownProperty<unknown>(jwk, 'kty');
  const crv = ownProperty<unknown>(jwk, 'crv');
  if (kty === 'OKP') {
    if (crv !== 'Ed25519') {
      throw new VericertsError(ErrorCodes.UNSUPPORTED_ALGORITHM);
    }
    if (typeof ownProperty<unknown>(jwk, 'x') !== 'string') {
      throw new VericertsError(ErrorCodes.DID_DOC_INVALID);
    }
    return jwk;
  }
  if (kty !== 'EC') {
    // EC / OKP 以外（RSA 等）は対応 alg で検証できない。
    throw new VericertsError(ErrorCodes.UNSUPPORTED_ALGORITHM);
  }
  if (crv !== 'P-256' && crv !== 'secp256k1') {
    throw new VericertsError(ErrorCodes.UNSUPPORTED_ALGORITHM);
  }
  if (
    typeof ownProperty<unknown>(jwk, 'x') !== 'string' ||
    typeof ownProperty<unknown>(jwk, 'y') !== 'string'
  ) {
    throw new VericertsError(ErrorCodes.DID_DOC_INVALID);
  }
  return jwk;
}

/**
 * 単一の VerificationMethod から検証鍵 JWK を取り出す。
 *
 * `publicKeyJwk` → `publicKeyMultibase` → `publicKeyHex` → Ed25519 の `publicKeyBase58` の順で評価する。
 * いずれの公開鍵表現も
 * 持たない場合は DID Document 不正（code `2010`）。
 *
 * @param vm 検証鍵を取り出す VerificationMethod。
 * @returns 公開鍵 JWK（EC または OKP）。
 */
export function verificationMethodToJwk(vm: VerificationMethod): PublicKeyJwk {
  // 鍵メンバは own 限定で読む。`createDidKey` / `resolveDidKey` が返す生成オブジェクトは通常
  // プロトタイプのため、`Object.prototype.publicKeyJwk` が汚染されていると本来の
  // `publicKeyMultibase` より攻撃者の JWK が優先されてしまう。
  const publicKeyJwk = ownProperty<PublicKeyJwk>(vm, 'publicKeyJwk');
  if (publicKeyJwk !== undefined) {
    return assertVerifiableJwk(publicKeyJwk);
  }
  const publicKeyMultibase = ownProperty<string>(vm, 'publicKeyMultibase');
  if (publicKeyMultibase !== undefined) {
    return multibaseToJwk(publicKeyMultibase);
  }
  const publicKeyHex = ownProperty<string>(vm, 'publicKeyHex');
  if (publicKeyHex !== undefined) {
    return hexToJwk(publicKeyHex);
  }
  const publicKeyBase58 = ownProperty<unknown>(vm, 'publicKeyBase58');
  if (
    ownProperty<unknown>(vm, 'type') === 'Ed25519VerificationKey2018' &&
    typeof publicKeyBase58 === 'string'
  ) {
    return ed25519Base58ToJwk(publicKeyBase58);
  }
  // 対応 alg で扱える公開鍵表現を持たない（未知の base58 / base64 / blockchainAccountId 等）。
  throw new VericertsError(ErrorCodes.DID_DOC_INVALID);
}

/** Ed25519VerificationKey2018 の 32 バイト公開鍵を JWK にする。 */
function ed25519Base58ToJwk(material: string): PublicKeyJwk {
  // base58 は二次時間。32 バイトの最大符号長（44 文字）をデコード前に検査する。
  if (material.length > 44) {
    throw new VericertsError(ErrorCodes.DID_DOC_INVALID);
  }
  let bytes: Uint8Array;
  try {
    bytes = base58.decode(material);
  } catch {
    throw new VericertsError(ErrorCodes.DID_DOC_INVALID);
  }
  return rawPublicKeyToJwk(bytes, ED25519_SPEC);
}
