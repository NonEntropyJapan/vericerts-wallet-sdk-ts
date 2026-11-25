/**
 * subjectPublicKeyInfo（SPKI・DER）→ JWS 検証鍵 JWK の変換（RFC 5280 §4.1.2.7 / RFC 5480）。
 *
 * X.509 証明書の公開鍵で **JWS**（SD-JWT VC の Issuer-signed JWT）を検証するために要る。
 * `trust/etsi-tsl/verify.ts` の `verifySignature` は SPKI を WebCrypto へそのまま渡せるが、
 * SD-JWT の検証入口 `verifySdJwt` は `issuerKey: PublicKeyJwk` を要求し、証明書側の表現
 * （SPKI）と鍵の表現（JWK）が噛み合わない。ここで 1 度だけ橋を架ける。
 *
 * **対応するのは EC P-256 だけである。** SD-JWT の Issuer 署名に使える alg は SDK の許可リスト
 * （`credential/vc/jws.ts` の `SUPPORTED_CREDENTIAL_ALGS` = `ES256` / `ES256K` / `EdDSA`）に限られ、
 * このうち X.509 の証明書鍵として現れるのは P-256（`id-ecPublicKey` + `prime256v1`）である。
 * RSA 鍵の証明書は SPKI としては正当でも SD-JWT の Issuer 署名には使えないため、`undefined` を
 * 返して呼び出し側の fail-closed に委ねる（ここで「変換できた」ことにすると、検証できない鍵で
 * 検証したつもりになる）。
 *
 * セキュリティ上の注意:
 * - 例外を投げず `undefined` で失敗を表す（戻り値に鍵素材・DER を含めないため）。
 * - 点は `@noble/curves` で曲線上に復元してから座標を取り出す（曲線外の点を JWK に化けさせない）。
 */

import { p256 } from '@noble/curves/nist.js';
import { base64urlnopad } from '@scure/base';
import type { PublicKeyJwk } from '../../identity/did.js';
import { type Asn1Node, decodeOid, readChildren, readNode } from '../asn1.js';

/** SEQUENCE / OID / BIT STRING の DER タグ。 */
const TAG_BIT_STRING = 0x03;
const TAG_OID = 0x06;
const TAG_SEQUENCE = 0x30;

/** `id-ecPublicKey`（RFC 5480 §2.1.1）。 */
const OID_EC_PUBLIC_KEY = '1.2.840.10045.2.1';
/** `prime256v1` / NIST P-256（RFC 5480 §2.1.1.1）。 */
const OID_PRIME256V1 = '1.2.840.10045.3.1.7';

/** EC 座標の長さ（P-256 は 32 バイト）。 */
const EC_COORDINATE_LENGTH = 32;

/** AlgorithmIdentifier が `id-ecPublicKey` + `prime256v1` かを確かめる。 */
function isP256Algorithm(algorithm: Asn1Node): boolean {
  if (algorithm.tag !== TAG_SEQUENCE) {
    return false;
  }
  const [algOid, curveOid] = readChildren(algorithm);
  if (algOid?.tag !== TAG_OID || curveOid?.tag !== TAG_OID) {
    return false;
  }
  return (
    decodeOid(algOid.content) === OID_EC_PUBLIC_KEY &&
    decodeOid(curveOid.content) === OID_PRIME256V1
  );
}

/**
 * SPKI（DER）を EC P-256 の公開鍵 JWK へ変換する。
 *
 * SubjectPublicKeyInfo ::= SEQUENCE { algorithm AlgorithmIdentifier, subjectPublicKey BIT STRING }。
 * `subjectPublicKey` の先頭 1 バイト（未使用ビット数）を除いた中身が SEC1 の曲線点である。
 *
 * @param spki 証明書の `subjectPublicKeyInfo`（`parseCertificate` の `spki`）。
 * @returns P-256 公開鍵 JWK（`{ kty:'EC', crv:'P-256', x, y }`）。P-256 でない / DER 不正 /
 *          曲線上の点でない場合は `undefined`。
 */
export function spkiToPublicKeyJwk(spki: Uint8Array): PublicKeyJwk | undefined {
  try {
    const info = readNode(spki);
    if (info.tag !== TAG_SEQUENCE) {
      return undefined;
    }
    const [algorithm, subjectPublicKey] = readChildren(info);
    if (algorithm === undefined || subjectPublicKey?.tag !== TAG_BIT_STRING) {
      return undefined;
    }
    if (!isP256Algorithm(algorithm) || subjectPublicKey.content.length === 0) {
      return undefined;
    }
    // `subjectPublicKey` の BIT STRING は常に未使用ビット 0 でなければならない（RFC 5280
    // §4.1.2.7 / RFC 5480 §2.2 の SEC1 点表現はオクテット境界に揃う）。0 以外は、同じ点を
    // 複数のバイト列で書ける（= 鍵の同一性判定がバイト列でずれる）ことを意味するので受けない。
    if (subjectPublicKey.content[0] !== 0x00) {
      return undefined;
    }
    // BIT STRING の先頭バイトは未使用ビット数。鍵の点はその次から始まる。
    const uncompressed = p256.Point.fromBytes(subjectPublicKey.content.subarray(1)).toBytes(false);
    return {
      kty: 'EC',
      crv: 'P-256',
      x: base64urlnopad.encode(uncompressed.subarray(1, 1 + EC_COORDINATE_LENGTH)),
      y: base64urlnopad.encode(uncompressed.subarray(1 + EC_COORDINATE_LENGTH)),
    };
  } catch {
    // DER 不正・曲線外の点。`undefined` は呼び出し側で「鍵を解決できなかった」に畳まれる。
    return undefined;
  }
}
