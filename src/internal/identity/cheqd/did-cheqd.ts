/**
 * did:cheqd の DID 形式と検証鍵の検査。
 *
 * ```text
 * did:cheqd:<名前空間>:<識別子>
 * did:cheqd:mainnet:de9786cd-ec53-458c-857c-9342cf264f80     # UUID 形式
 * did:cheqd:testnet:TAwT8WVt3dz2DBAifwuSkn                   # Indy 形式（base58btc 21〜22 文字）
 * ```
 *
 * 名前空間は必須で、省略形（`did:cheqd:<識別子>`）は接続先で意味が変わり DID 単体で宛先が決まらないため
 * `2001`。識別子は UUID（8-4-4-4-12 の 16 進）か Indy 形式だけを受理する。
 *
 * 鍵は Ed25519 だけを対象にする（`Ed25519VerificationKey2018`＋`publicKeyBase58`、
 * `Ed25519VerificationKey2020`＋`publicKeyMultibase`、`JsonWebKey2020`＋OKP/Ed25519 の `publicKeyJwk`）。
 * それ以外の種別・曲線は `2010`（`reason: "cheqd_key_unsupported"`）、対象の種別で鍵が読めなければ
 * `2010`（`reason: "cheqd_key_invalid"`）。
 *
 * セキュリティ上の注意: 例外の `context` に DID・鍵の内容を含めない。
 */

import { base58, base64urlnopad } from '@scure/base';
import { ErrorCodes, VericertsError } from '../../errors.js';
import { ownProperty } from '../../prototype-safety/own-property.js';
import type { VerificationMethod } from '../did.js';
import { MAX_DID_LENGTH } from '../did-format.js';
import { multibaseBase58Decode } from '../multibase.js';

/** DID の接頭辞。 */
const DID_CHEQD_PREFIX = 'did:cheqd:';

/** 名前空間（ABNF: `1*namespace-char`、`namespace-char = ALPHA / DIGIT`）。 */
const NAMESPACE_PATTERN = /^[A-Za-z0-9]+$/;

/** UUID（RFC 4122 の 8-4-4-4-12 の 16 進）。 */
export const UUID_PATTERN =
  /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;

/** Indy 形式（最初の Ed25519 鍵の SHA-256 先頭 16 バイトの base58btc。21〜22 文字）。 */
const INDY_PATTERN = /^[1-9A-HJ-NP-Za-km-z]{21,22}$/;

/** Ed25519 公開鍵の長さ。 */
const ED25519_KEY_BYTES = 32;

/** Ed25519 の multicodec（`0xed 0x01`）。 */
const ED25519_MULTICODEC = Uint8Array.of(0xed, 0x01);

/** 解析済みの did:cheqd。 */
export interface ParsedDidCheqd {
  readonly namespace: string;
  readonly identifier: string;
  /** 識別子の形式。 */
  readonly style: 'uuid' | 'indy';
}

function invalidDid(reason: string): VericertsError {
  return new VericertsError(ErrorCodes.INVALID_DID, { context: { reason } });
}

/**
 * did:cheqd を名前空間必須で解析する。
 *
 * @throws 名前空間の省略（code `2001`、`cheqd_namespace_required`）、接頭辞違い・長さ超過・
 *   名前空間 / 識別子の形式不正（code `2001`、`cheqd_invalid_did`）。
 */
export function parseDidCheqd(did: string): ParsedDidCheqd {
  if (!did.startsWith(DID_CHEQD_PREFIX) || did.length > MAX_DID_LENGTH) {
    throw invalidDid('cheqd_invalid_did');
  }
  const segments = did.slice(DID_CHEQD_PREFIX.length).split(':');
  if (segments.length === 1 && segments[0] !== '') {
    throw invalidDid('cheqd_namespace_required');
  }
  if (segments.length !== 2) {
    throw invalidDid('cheqd_invalid_did');
  }
  const [namespace, identifier] = segments as [string, string];
  if (!NAMESPACE_PATTERN.test(namespace)) {
    throw invalidDid('cheqd_invalid_did');
  }
  if (UUID_PATTERN.test(identifier)) {
    return { namespace, identifier, style: 'uuid' };
  }
  if (INDY_PATTERN.test(identifier)) {
    return { namespace, identifier, style: 'indy' };
  }
  throw invalidDid('cheqd_invalid_did');
}

function keyError(reason: 'cheqd_key_unsupported' | 'cheqd_key_invalid'): VericertsError {
  return new VericertsError(ErrorCodes.DID_DOC_INVALID, { context: { reason } });
}

/** `decode` が 32 バイトの鍵を返せば `true`（例外は不正として `false`）。 */
function decodesToKey(decode: () => Uint8Array, prefix?: Uint8Array): boolean {
  let bytes: Uint8Array;
  try {
    bytes = decode();
  } catch {
    return false;
  }
  const offset = prefix?.length ?? 0;
  if (bytes.length !== offset + ED25519_KEY_BYTES) {
    return false;
  }
  return prefix === undefined || prefix.every((byte, i) => bytes[i] === byte);
}

/**
 * 検証メソッドが Ed25519 の鍵であることを確かめる。
 *
 * @throws Ed25519 以外の種別・曲線（code `2010`、`cheqd_key_unsupported`）、
 *   対象の種別で鍵が読めない（code `2010`、`cheqd_key_invalid`）。
 */
export function assertEd25519VerificationMethod(vm: VerificationMethod): void {
  // 複数表現を許すと、検証した Ed25519 鍵と下流が優先する JWK が異なる場合がある。
  const materialCount = [
    'publicKeyBase58',
    'publicKeyMultibase',
    'publicKeyJwk',
    'publicKeyHex',
  ].filter((key) => ownProperty<unknown>(vm, key) !== undefined).length;
  if (materialCount > 1) {
    throw keyError('cheqd_key_invalid');
  }
  const type = ownProperty<unknown>(vm, 'type');
  let valid: boolean;
  if (type === 'Ed25519VerificationKey2018') {
    const material = ownProperty<unknown>(vm, 'publicKeyBase58');
    // 32 バイトの base58 は最大 44 文字。二次時間のデコード前に長さを制限する。
    valid =
      typeof material === 'string' &&
      material.length <= 44 &&
      decodesToKey(() => base58.decode(material));
  } else if (type === 'Ed25519VerificationKey2020') {
    const material = ownProperty<unknown>(vm, 'publicKeyMultibase');
    valid =
      typeof material === 'string' &&
      decodesToKey(() => multibaseBase58Decode(material), ED25519_MULTICODEC);
  } else if (type === 'JsonWebKey2020') {
    const jwk = ownProperty<unknown>(vm, 'publicKeyJwk');
    if (typeof jwk !== 'object' || jwk === null) {
      throw keyError('cheqd_key_invalid');
    }
    if (
      ownProperty<unknown>(jwk, 'kty') !== 'OKP' ||
      ownProperty<unknown>(jwk, 'crv') !== 'Ed25519'
    ) {
      throw keyError('cheqd_key_unsupported');
    }
    const x = ownProperty<unknown>(jwk, 'x');
    valid = typeof x === 'string' && decodesToKey(() => base64urlnopad.decode(x));
  } else {
    throw keyError('cheqd_key_unsupported');
  }
  if (!valid) {
    throw keyError('cheqd_key_invalid');
  }
}
