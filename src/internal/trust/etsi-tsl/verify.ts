/**
 * WebCrypto を用いた署名検証プリミティブ（trust/etsi-tsl）。
 *
 * XMLDSig（LOTL/TSL）と X.509 証明書チェーンの署名検証で共有する。RSA（RSASSA-PKCS1-v1_5）は
 * `@noble/curves` が提供しないため、Node 20+ / ブラウザ双方で利用可能な標準の `crypto.subtle` を
 * 用いる（新規依存を増やさない）。SPKI からの公開鍵 import と ECDSA / RSA 検証を提供する。
 *
 * セキュリティ上の注意:
 * - 検証は fail-closed。import 失敗・未対応アルゴリズム・検証エラーはすべて `false` を返す
 *   （例外を握りつぶし、呼び出し側で XMLDSIG_VERIFICATION_FAILED / QUALIFIED_CERT_INVALID に正規化）。
 * - modulus が 2048 bit 未満、またはパースできない RSA 公開鍵は `false` を返して拒否する。
 */

import { MIN_RSA_MODULUS_BITS, rsaModulusBitLength } from './rsa-key-size.js';
import type { CertSignatureAlg } from './x509.js';

/** ECDSA P-256 署名を raw(P1363・64B) と DER の双方で受理するためのしきい値。 */
const ECDSA_P256_RAW_LENGTH = 64;

/** `crypto.subtle` を取得する（未提供環境では undefined）。 */
function getSubtle(): SubtleCrypto | undefined {
  return globalThis.crypto?.subtle;
}

/** WebCrypto の import / verify パラメータ。 */
interface AlgParams {
  readonly importAlgorithm: RsaHashedImportParams | EcKeyImportParams;
  readonly verifyAlgorithm: AlgorithmIdentifier | EcdsaParams;
}

/** 証明書署名アルゴリズム → WebCrypto パラメータ。 */
const ALG_PARAMS: Readonly<Record<CertSignatureAlg, AlgParams>> = {
  'RSASSA-PKCS1-v1_5-SHA256': {
    importAlgorithm: { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    verifyAlgorithm: { name: 'RSASSA-PKCS1-v1_5' },
  },
  'ECDSA-P256-SHA256': {
    importAlgorithm: { name: 'ECDSA', namedCurve: 'P-256' },
    verifyAlgorithm: { name: 'ECDSA', hash: 'SHA-256' },
  },
};

/**
 * SPKI 公開鍵と署名アルゴリズムを用いて署名を検証する。
 *
 * @param alg 署名アルゴリズム（証明書 / XMLDSig で決定）。
 * @param spki subjectPublicKeyInfo（DER）。
 * @param signature 署名バイト列。ECDSA は raw(64B) を DER に変換して渡す。
 * @param data 署名対象データ（ハッシュ前の生バイト。WebCrypto が内部でハッシュする）。
 * @returns 署名が有効なら `true`。import / 検証に失敗した場合は `false`（fail-closed）。
 */
export async function verifySignature(
  alg: CertSignatureAlg,
  spki: Uint8Array,
  signature: Uint8Array,
  data: Uint8Array,
): Promise<boolean> {
  const subtle = getSubtle();
  if (subtle === undefined) {
    return false;
  }
  const params = ALG_PARAMS[alg];
  if (alg === 'RSASSA-PKCS1-v1_5-SHA256') {
    // 鍵長が小さい RSA も SPKI として正当なら WebCrypto は import・検証できるため、importKey の前に弾く。
    const bits = rsaModulusBitLength(spki);
    if (bits === undefined || bits < MIN_RSA_MODULUS_BITS) {
      return false;
    }
  }
  try {
    const key = await subtle.importKey('spki', toArrayBuffer(spki), params.importAlgorithm, false, [
      'verify',
    ]);
    const sig =
      alg === 'ECDSA-P256-SHA256' ? normalizeEcdsaSignature(signature) : toArrayBuffer(signature);
    return await subtle.verify(params.verifyAlgorithm, key, sig, toArrayBuffer(data));
  } catch {
    // import / verify 失敗（不正な鍵・署名形式・未対応曲線等）は改ざん相当として false。
    return false;
  }
}

/**
 * ECDSA 署名を WebCrypto が要求する raw(P1363・r||s) 形式へ正規化する。
 *
 * X.509 の ECDSA 署名は DER（SEQUENCE{ r INTEGER, s INTEGER }）でエンコードされるため、
 * 64B raw でない場合は DER とみなして r/s を抽出する。
 */
function normalizeEcdsaSignature(signature: Uint8Array): ArrayBuffer {
  if (signature.length === ECDSA_P256_RAW_LENGTH) {
    return toArrayBuffer(signature);
  }
  return toArrayBuffer(derEcdsaToRaw(signature));
}

/** DER の ECDSA 署名（SEQUENCE{ r, s }）を 64B raw(P1363) へ変換する（P-256 固定）。 */
function derEcdsaToRaw(der: Uint8Array): Uint8Array {
  const componentLength = ECDSA_P256_RAW_LENGTH / 2;
  // 0x30 len 0x02 rlen R 0x02 slen S
  let pos = 2;
  if (der[pos] !== 0x02) {
    throw new Error('bad ecdsa der');
  }
  const rLen = der[pos + 1] as number;
  const r = trimInteger(der.subarray(pos + 2, pos + 2 + rLen), componentLength);
  pos = pos + 2 + rLen;
  if (der[pos] !== 0x02) {
    throw new Error('bad ecdsa der');
  }
  const sLen = der[pos + 1] as number;
  const s = trimInteger(der.subarray(pos + 2, pos + 2 + sLen), componentLength);
  const raw = new Uint8Array(ECDSA_P256_RAW_LENGTH);
  raw.set(r, componentLength - r.length);
  raw.set(s, ECDSA_P256_RAW_LENGTH - s.length);
  return raw;
}

/** DER INTEGER から先頭 0x00 パディングを除去し、右詰めの固定長成分にする。 */
function trimInteger(bytes: Uint8Array, maxLength: number): Uint8Array {
  let start = 0;
  while (start < bytes.length - 1 && bytes[start] === 0x00) {
    start++;
  }
  const trimmed = bytes.subarray(start);
  if (trimmed.length > maxLength) {
    throw new Error('ecdsa component too large');
  }
  return trimmed;
}

/** Uint8Array を（backing buffer に依存しない）独立した ArrayBuffer へコピーする。 */
function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(bytes.length);
  copy.set(bytes);
  return copy.buffer;
}
