/**
 * P-256 署名・検証・鍵導出の純粋関数モジュール（WebAuthn / EUDI / ES256 互換）。
 *
 * `../signer.ts` から責務分離した実装で、公開 API の入口は従来どおり `signer.ts` に一本化する
 * （利用側は本モジュールを直接 import せず `signer.ts` を経由する）。
 *
 * sign は「すでにハッシュ済みのダイジェスト」を入力とする前提で、`@noble` の内部ハッシュ
 * （既定 sha256）を無効化する `prehash: false` を必ず指定する。したがって `digest` は呼び出し側で
 * 計算済みの 32 バイトでなければならない。P-256 は recoverable 署名（recovery id 付き・署名からの
 * 公開鍵復元）を提供しない。
 *
 * セキュリティ上の注意:
 * - privateKey / digest などの秘密・入力データは、例外メッセージや `context` に一切含めない。
 * - `@noble` 由来の例外は、メッセージに秘密が含まれ得るため `cause` を渡さず握りつぶす
 *   （`../signer.ts` の元実装と同様）。
 */

import { p256 } from '@noble/curves/nist.js';
import { ErrorCodes, VericertsError } from '../../errors.js';
import { ownProperty } from '../../prototype-safety/own-property.js';
import {
  assertDigest,
  DIGEST_LENGTH,
  type EcdsaSignatureEncoding,
  type VerifyP256Options,
  verifyEcdsaCanonical,
} from './signature-format.js';

/**
 * P-256 で署名を生成する（WebAuthn / EUDI / ES256 互換）。
 *
 * P-256 は recoverable 署名（recovery id 付き・署名からの公開鍵復元）を提供しない。
 * WebAuthn / EUDI / ES256 用途では公開鍵が別途提供されるため recovery は不要。
 *
 * RFC6979 による決定論的署名と low-s 正規化を行い、IEEE P1363（raw）形式の 64 バイト
 * （`r(32) || s(32)`）を返す。
 *
 * @param digest 署名対象のダイジェスト（32 バイト）。
 * @param privateKey 秘密鍵（32 バイト）。
 * @returns 64 バイトの P1363 署名。
 * @throws privateKey が不正な場合（VericertsError、code `1003`）、
 *         digest 長不正・署名演算失敗の場合（VericertsError、code `1020`）。
 */
export function signP256(digest: Uint8Array, privateKey: Uint8Array): Uint8Array {
  assertDigest(digest);
  if (!p256.utils.isValidSecretKey(privateKey)) {
    throw new VericertsError(ErrorCodes.INVALID_PRIVATE_KEY);
  }
  try {
    // format 既定 'compact'（64B P1363）。prehash:false でダイジェスト入力。
    return p256.sign(digest, privateKey, { prehash: false });
  } catch {
    // @noble 由来の例外メッセージに秘密が含まれ得るため cause は渡さない。
    throw new VericertsError(ErrorCodes.SIGN_FAILED);
  }
}

/**
 * P-256 署名を検証する。
 *
 * 既定では **RFC 7515 §3.1 準拠の厳密 64 バイト `r || s`（`encoding: 'p1363'`）のみ**を受理し、
 * low-S を強制する。以前は「64 バイト以外はすべて DER」として解釈していたため、正規の 64 バイト署名を
 * DER へ再エンコードした 71 バイト署名も通過し、同一クレームに対する有効な JWS が複数成立していた。
 *
 * DER を返す HSM / KMS の署名を直接検証する非 JWS 用途は `options.encoding: 'der'` で明示的に
 * opt-in する。P-256 は recovery 付き署名を扱わないため `'recovered'` は指定できない。
 *
 * 第三者 Issuer / KMS が返す high-S 署名を受理する必要がある場合は `options.allowHighS` を使う
 * （既定 `false`）。
 *
 * @param digest 検証対象のダイジェスト（32 バイト）。
 * @param signature 署名バイト列（`options.encoding` に従う）。
 * @param publicKey 公開鍵（圧縮 33 バイト / 非圧縮 65 バイト）。
 * @param options エンコーディング・low-S の受理範囲。既定は `'p1363'` かつ low-S 強制。
 * @returns 署名が有効かつ指定エンコーディングとして正準なら `true`、それ以外は `false`。
 */
export function verifyP256(
  digest: Uint8Array,
  signature: Uint8Array,
  publicKey: Uint8Array,
  options: VerifyP256Options = {},
): boolean {
  if (digest.length !== DIGEST_LENGTH) {
    return false;
  }
  return verifyEcdsaCanonical(
    p256,
    digest,
    signature,
    publicKey,
    // `verifySecp256k1` と同じ理由で自身のプロパティに限って読む。
    ownProperty<EcdsaSignatureEncoding>(options, 'encoding') ?? 'p1363',
    ownProperty<boolean>(options, 'allowHighS') ?? false,
  );
}

/**
 * P-256 秘密鍵から公開鍵を導出する。
 *
 * @param privateKey 秘密鍵（32 バイト）。
 * @param compressed 圧縮形式にするか（既定 `true` = 33 バイト、`false` = 65 バイト非圧縮）。
 * @returns 公開鍵バイト列。
 * @throws privateKey が不正な場合（VericertsError、code `1003`）。
 */
export function getP256PublicKey(privateKey: Uint8Array, compressed = true): Uint8Array {
  if (!p256.utils.isValidSecretKey(privateKey)) {
    throw new VericertsError(ErrorCodes.INVALID_PRIVATE_KEY);
  }
  try {
    return p256.getPublicKey(privateKey, compressed);
  } catch {
    throw new VericertsError(ErrorCodes.INVALID_PRIVATE_KEY);
  }
}
