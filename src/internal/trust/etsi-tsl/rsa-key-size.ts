/**
 * RSA 公開鍵（SPKI）の modulus ビット長の算出（trust/etsi-tsl）。
 *
 * ETSI TSL の RSA 署名検証には 2048 bit 以上の RSA 鍵が必要。短い鍵も有効な SPKI なら
 * WebCrypto で import・検証できるため、署名検証の入口（`verify.ts` の `verifySignature`）で
 * 本モジュールの結果を見て弱い鍵を拒否する。ASN.1 の読み取りは `trust/asn1.ts` を使う。
 *
 * SubjectPublicKeyInfo ::= SEQUENCE {
 *   algorithm        AlgorithmIdentifier { OID rsaEncryption, NULL },
 *   subjectPublicKey BIT STRING }   -- 中身は RSAPublicKey
 * RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }
 */

import { decodeOid, readChildren, readNode } from '../asn1.js';

/** 署名検証に使う RSA 公開鍵の modulus 長の下限（bit）。上限は設けない。 */
export const MIN_RSA_MODULUS_BITS = 2048;

const TAG_INTEGER = 0x02;
const TAG_BIT_STRING = 0x03;
const TAG_OID = 0x06;
const TAG_SEQUENCE = 0x30;

/** rsaEncryption（PKCS #1）。 */
const OID_RSA_ENCRYPTION = '1.2.840.113549.1.1.1';

/**
 * SPKI（DER）から RSA modulus の実ビット長を求める。
 *
 * modulus INTEGER の先頭 0x00（符号ビット回避のパディング）を除き、最上位バイトの先頭ゼロビットを
 * 除いた長さを数える（2048bit 鍵 = 256 バイトで最上位ビットが 1）。
 *
 * @param spki subjectPublicKeyInfo（DER）。
 * @returns modulus のビット長。RSA 以外の鍵・DER として不正・負数や 0 の modulus は `undefined`
 *          （呼び出し側で拒否する）。
 */
export function rsaModulusBitLength(spki: Uint8Array): number | undefined {
  try {
    const root = readNode(spki);
    if (root.tag !== TAG_SEQUENCE || root.totalLength !== spki.length) {
      return undefined;
    }
    const [algorithm, subjectPublicKey, ...extra] = readChildren(root);
    if (
      algorithm === undefined ||
      subjectPublicKey === undefined ||
      extra.length > 0 ||
      algorithm.tag !== TAG_SEQUENCE ||
      subjectPublicKey.tag !== TAG_BIT_STRING
    ) {
      return undefined;
    }
    const oid = readChildren(algorithm)[0];
    if (oid?.tag !== TAG_OID || decodeOid(oid.content) !== OID_RSA_ENCRYPTION) {
      return undefined;
    }
    // BIT STRING の先頭 1 バイトは未使用ビット数（RSAPublicKey は完全なバイト列なので 0）。
    if (subjectPublicKey.content[0] !== 0x00) {
      return undefined;
    }
    const rsaKey = readNode(subjectPublicKey.content.subarray(1));
    if (rsaKey.tag !== TAG_SEQUENCE || rsaKey.totalLength !== subjectPublicKey.content.length - 1) {
      return undefined;
    }
    const [modulus, exponent, ...rest] = readChildren(rsaKey);
    if (
      modulus === undefined ||
      exponent === undefined ||
      rest.length > 0 ||
      modulus.tag !== TAG_INTEGER ||
      exponent.tag !== TAG_INTEGER
    ) {
      return undefined;
    }
    return bitLengthOfPositiveInteger(modulus.content);
  } catch {
    // 想定外の例外も「パース不能」として扱い、verifySignature を fail-closed（false）に保つ。
    return undefined;
  }
}

/** DER INTEGER（big-endian・two's complement）の値部から正の整数の実ビット長を求める。 */
function bitLengthOfPositiveInteger(content: Uint8Array): number | undefined {
  const first = content[0];
  if (first === undefined || (first & 0x80) !== 0) {
    // 空・負数は modulus として不正。
    return undefined;
  }
  let start = 0;
  while (start < content.length && content[start] === 0x00) {
    start++;
  }
  const top = content[start];
  if (top === undefined) {
    // 値が 0。
    return undefined;
  }
  return (content.length - start - 1) * 8 + (32 - Math.clz32(top));
}
