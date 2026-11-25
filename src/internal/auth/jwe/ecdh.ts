/**
 * ECDH-ES 鍵合意（RFC 7518 §4.6）と Concat KDF（NIST SP 800-56A §5.8.1 / RFC 7518 §4.6.2）。
 *
 * `direct_post.jwt` で応答を暗号化する際の鍵合意を行う。
 * `jwe.ts` から分離した鍵合意レイヤ（1 ファイル 300 行以下に収めるため）。対応曲線は P-256 のみ。
 *
 * `submitPresentation` が受け取るエラーコードは次のとおり。
 *
 * | 失敗                                                   | code   |
 * | ------------------------------------------------------ | ------ |
 * | 受信者 JWK の形式不正（`kty` / `crv` / 座標長）        | `8036` |
 * | 受信者 JWK の点が曲線上にない（形式は正しいが無効な鍵）| `8036` |
 * | エフェメラル鍵生成 / Concat KDF の失敗                 | `8037` |
 *
 * セキュリティ上の注意:
 * - 共有秘密・エフェメラル秘密鍵・受信者 JWK を例外メッセージ・`context`・`cause` に一切含めない。
 *   @noble 由来の例外（`bad point: is not on curve` 等）は鍵素材を含み得るため `cause` を渡さない。
 * - エフェメラル鍵ペアは鍵合意 1 回ごとに新規生成する（RFC 7518 §4.6.1: 再利用禁止）。
 */

import { p256 } from '@noble/curves/nist.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { concatBytes } from '../../asset/bytes.js';
import { ErrorCodes, VericertsError } from '../../errors.js';
import type { PublicKeyJwk } from '../../identity/did.js';
import { toEpkJwk } from '../../identity/jwt/epk-jwk.js';
import { jwkToUncompressedPublicKey, SUPPORTED_EC_CRV } from '../../identity/jwt/jwk-key.js';

/** EC 座標 / 導出鍵の長さ（バイト）。A256GCM / A256KW の鍵長でもある。 */
export const KEY_LENGTH = 32;
/** Concat KDF が導出する鍵長（ビット）。A256GCM / A256KW とも 256bit。 */
const KEYDATALEN_BITS = 256;

/** ECDH-ES 鍵合意の結果（JWE protected header の `epk` と Concat KDF 出力）。 */
export interface EcdhAgreement {
  /** エフェメラル公開鍵の JWK（protected header の `epk` にそのまま載せる）。 */
  readonly epk: Record<string, string>;
  /** Concat KDF が導出した 32 バイト鍵（direct なら CEK、Key Wrapping なら KEK）。 */
  readonly derived: Uint8Array;
}

/** 32bit ビッグエンディアン整数を 4 バイトへ直列化する（Concat KDF の長さプレフィックス）。 */
function uint32BE(value: number): Uint8Array {
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, value, false);
  return out;
}

/** `uint32BE(length) || bytes` 形式（Concat KDF の `Datalen || Data`）へ直列化する。 */
function lengthPrefixed(bytes: Uint8Array): Uint8Array {
  return concatBytes(uint32BE(bytes.length), bytes);
}

/**
 * Concat KDF（NIST SP 800-56A §5.8.1 / RFC 7518 §4.6.2）で共有秘密から 256bit 鍵を導出する。
 *
 * `keydatalen` が SHA-256 の出力長（256bit）と一致するためラウンドは 1 回で足りる。
 *
 * @param sharedSecret ECDH 共有秘密 `Z`（P-256 の x 座標 32 バイト）。
 * @param algorithmId `AlgorithmID`（direct なら `enc` 値、Key Wrapping なら `alg` 値）。
 * @param apu PartyUInfo の生バイト列。
 * @param apv PartyVInfo の生バイト列。
 * @returns 導出された 32 バイト鍵。
 */
function concatKdf(
  sharedSecret: Uint8Array,
  algorithmId: string,
  apu: Uint8Array,
  apv: Uint8Array,
): Uint8Array {
  const input = concatBytes(
    uint32BE(1), // round counter
    sharedSecret,
    lengthPrefixed(new TextEncoder().encode(algorithmId)),
    lengthPrefixed(apu),
    lengthPrefixed(apv),
    uint32BE(KEYDATALEN_BITS),
  );
  return sha256(input);
}

/**
 * 受信者の EC 公開鍵 JWK を SEC1 非圧縮バイト列へ変換する。
 *
 * `jwkToUncompressedPublicKey` には DID 由来の JWK と同じ `INVALID_DID`（2001）を渡し、
 * OID4VP 応答暗号化の文脈では `VP_RESPONSE_ENCRYPTION_UNSUPPORTED`（8036）へ正規化する。
 *
 * @throws `kty` / `crv` / 座標が不正な場合（VericertsError、code `8036`）。
 */
function recipientPublicKey(jwk: PublicKeyJwk): Uint8Array {
  try {
    return jwkToUncompressedPublicKey(jwk, {
      expectedCrv: SUPPORTED_EC_CRV,
      errorCode: ErrorCodes.INVALID_DID,
    });
  } catch {
    // JWK 本文を漏らさないため cause は握りつぶす。
    throw new VericertsError(ErrorCodes.VP_RESPONSE_ENCRYPTION_UNSUPPORTED, {
      context: { reason: 'unsupported_encryption_key' },
    });
  }
}

/**
 * エフェメラル鍵ペアと受信者公開鍵から ECDH 共有秘密 `Z`（x 座標 32 バイト）を求める。
 *
 * `kty` / `crv` / 座標長が形式的に正しくても点が曲線上に無い JWK があり得る
 * （`jwkToUncompressedPublicKey` は座標長しか見ない）。@noble はその場合に生の
 * `Error("bad point: is not on curve")` を投げるため、受信者鍵が使えない旨の 8036 へ正規化する。
 *
 * @throws 受信者鍵の点が無効な場合（VericertsError、code `8036`）。
 */
function deriveSharedSecret(ephemeralSecret: Uint8Array, recipient: Uint8Array): Uint8Array {
  try {
    // getSharedSecret は圧縮点（0x02/0x03 プレフィックス + x）を返すため、先頭 1 バイトを落とす。
    return p256.getSharedSecret(ephemeralSecret, recipient).slice(1);
  } catch {
    // 例外メッセージが鍵素材を含み得るため cause は渡さない。
    throw new VericertsError(ErrorCodes.VP_RESPONSE_ENCRYPTION_UNSUPPORTED, {
      context: { reason: 'invalid_encryption_key_point' },
    });
  }
}

/**
 * 新規エフェメラル鍵ペアで受信者鍵と ECDH-ES 鍵合意し、Concat KDF で 256bit 鍵を導出する
 * （RFC 7518 §4.6）。
 *
 * @param recipientJwk 受信者（Verifier）の EC 公開鍵 JWK（`crv=P-256`）。
 * @param algorithmId Concat KDF の `AlgorithmID`（direct なら `enc` 値、Key Wrapping なら `alg` 値）。
 * @param apu PartyUInfo の生バイト列。
 * @param apv PartyVInfo の生バイト列。
 * @returns protected header 用の `epk` と導出鍵。
 * @throws 受信者鍵が未対応 / 点が無効な場合（VericertsError、code `8036`）、
 *         エフェメラル鍵生成・鍵導出に失敗した場合（VericertsError、code `8037`）。
 */
export function agreeEphemeralKey(
  recipientJwk: PublicKeyJwk,
  algorithmId: string,
  apu: Uint8Array,
  apv: Uint8Array,
): EcdhAgreement {
  const recipient = recipientPublicKey(recipientJwk);

  // エフェメラル鍵は鍵合意ごとに新規生成する（RFC 7518 §4.6.1: 再利用禁止）。
  let ephemeralSecret: Uint8Array;
  let ephemeralPublic: Uint8Array;
  try {
    ephemeralSecret = p256.utils.randomSecretKey();
    ephemeralPublic = p256.getPublicKey(ephemeralSecret, false);
  } catch {
    throw new VericertsError(ErrorCodes.VP_RESPONSE_ENCRYPTION_FAILED, {
      context: { reason: 'ephemeral_key_generation_failed' },
    });
  }

  const sharedSecret = deriveSharedSecret(ephemeralSecret, recipient);
  let derived: Uint8Array;
  try {
    derived = concatKdf(sharedSecret, algorithmId, apu, apv);
  } catch {
    throw new VericertsError(ErrorCodes.VP_RESPONSE_ENCRYPTION_FAILED, {
      context: { reason: 'key_derivation_failed' },
    });
  }
  return { epk: toEpkJwk(ephemeralPublic), derived };
}
