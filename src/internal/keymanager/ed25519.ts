/**
 * EdDSA（Ed25519）署名・検証の純粋関数モジュール。
 *
 * `@noble/curves` の `ed25519` をラップし、JWS `alg: EdDSA` / `crv: Ed25519` / `kty: OKP`
 * 用の署名・検証・公開鍵導出を提供する。
 *
 * 隣接する `signer.ts`（ECDSA）とは前提が異なるため、意図的に別モジュールへ分離している:
 * - `signer.ts` は「ハッシュ済み 32 バイト digest」を入力とし `prehash: false` を強制する
 *   digest ベースの ECDSA 専用モジュール。
 * - Ed25519（RFC 8032 の PureEdDSA）は事前ハッシュを行わず、メッセージそのものに署名する。
 *   したがって本モジュールの `signEd25519` / `verifyEd25519` は digest ではなくメッセージ
 *   （JWS では signing-input）を受け取る。
 *
 * 鍵表現の注意:
 * - Ed25519 の秘密鍵は「32 バイトのシード」であり、ECDSA のようなスカラー値ではない。
 *   実際の署名スカラーと nonce はシードの SHA-512 から導出される（RFC 8032 §5.1.5）。
 *   したがって任意の 32 バイトが有効なシードであり、範囲検査は長さ検査のみで足りる。
 * - 公開鍵は 32 バイトの圧縮エドワーズ点（SEC1 のような圧縮 / 非圧縮の別はない）。
 *
 * スコープ境界:
 * - KeyManager クラス / Signer インターフェースは作らない。純粋関数のみを公開する。
 * - JWK ⇔ 生バイト列の相互変換は上位（`identity/jwt/jwt-codec.ts` 等）の責務とする。
 *
 * セキュリティ上の注意:
 * - privateKey / message などの秘密・入力データは、例外メッセージや `context` に一切含めない。
 * - エラーは `VericertsError` に正規化する。`@noble` 由来の例外は
 *   メッセージに秘密が含まれ得るため、`cause` を渡さず握りつぶす（`signer.ts` と同様）。
 */

import { ed25519 } from '@noble/curves/ed25519.js';
import { ErrorCodes, VericertsError } from '../errors.js';

/** Ed25519 公開鍵の固定長（32 バイトの圧縮エドワーズ点）。 */
export const ED25519_PUBLIC_KEY_LENGTH = 32;

/**
 * Ed25519 秘密鍵（シード）の固定長（32 バイト）。
 *
 * Ed25519 の秘密鍵はスカラーではなくシードで、署名スカラーはシードの SHA-512 から導出される。
 */
export const ED25519_SEED_LENGTH = 32;

/**
 * Ed25519（PureEdDSA / RFC 8032）でメッセージに署名する。
 *
 * ECDSA と異なり事前ハッシュを行わない。JWS では signing-input
 * （`base64url(header).base64url(payload)` の UTF-8 バイト列）をそのまま渡す。
 *
 * @param message 署名対象のメッセージ（長さ制限なし）。
 * @param privateKey 秘密鍵シード（32 バイト）。
 * @returns 64 バイトの署名（`R(32) || S(32)`）。
 * @throws privateKey がシード長でない場合（VericertsError、code `1003`）、
 *         署名演算失敗の場合（VericertsError、code `1020`）。
 */
export function signEd25519(message: Uint8Array, privateKey: Uint8Array): Uint8Array {
  if (privateKey.length !== ED25519_SEED_LENGTH) {
    // 秘密鍵の内容はメッセージに含めない。
    throw new VericertsError(ErrorCodes.INVALID_PRIVATE_KEY);
  }
  try {
    return ed25519.sign(message, privateKey);
  } catch {
    // @noble 由来の例外メッセージに秘密が含まれ得るため cause は渡さない。
    throw new VericertsError(ErrorCodes.SIGN_FAILED);
  }
}

/**
 * Ed25519 署名を検証する。
 *
 * `verifyP256` / `verifySecp256k1` と同じく、形式不正・検証失敗のいずれも例外ではなく
 * `false` を返す（決して throw しない）。
 *
 * 検証は RFC 8032 準拠（`zip215: false`）で行う。`@noble/curves` の既定は `zip215: true` で、
 * R / A の非正準エンコーディング（`p` 以上の値や非正準な符号ビット）まで受理するため、既定のままだと
 * 本モジュールの PureEdDSA / RFC 8032
 * という前提と受理集合が食い違う。他 Verifier が RFC 8032 で拒否する署名を本 SDK だけが受理すると
 * 相互運用上の乖離（同一 VC の検証結果が実装間で割れる）になるため、明示的に狭い方へ倒す。
 *
 * @param message 署名対象のメッセージ（JWS では signing-input）。
 * @param signature 署名（64 バイト）。
 * @param publicKey 公開鍵（32 バイト）。
 * @returns 署名が有効なら `true`、無効・形式不正なら `false`。
 */
export function verifyEd25519(
  message: Uint8Array,
  signature: Uint8Array,
  publicKey: Uint8Array,
): boolean {
  if (publicKey.length !== ED25519_PUBLIC_KEY_LENGTH) {
    return false;
  }
  try {
    // @noble の引数順は (signature, message, publicKey)。
    // zip215: false で RFC 8032 準拠の受理集合にする（既定の true は非正準エンコーディングを許す）。
    return ed25519.verify(signature, message, publicKey, { zip215: false });
  } catch {
    // 不正な署名・公開鍵フォーマット等は検証失敗（false）として扱う。
    return false;
  }
}

/**
 * Ed25519 秘密鍵シードから公開鍵を導出する。
 *
 * @param privateKey 秘密鍵シード（32 バイト）。
 * @returns 32 バイトの公開鍵。
 * @throws privateKey がシード長でない / 導出に失敗した場合（VericertsError、code `1003`）。
 */
export function getEd25519PublicKey(privateKey: Uint8Array): Uint8Array {
  if (privateKey.length !== ED25519_SEED_LENGTH) {
    throw new VericertsError(ErrorCodes.INVALID_PRIVATE_KEY);
  }
  try {
    return ed25519.getPublicKey(privateKey);
  } catch {
    // @noble 由来の例外メッセージに秘密が含まれ得るため cause は渡さない。
    throw new VericertsError(ErrorCodes.INVALID_PRIVATE_KEY);
  }
}
