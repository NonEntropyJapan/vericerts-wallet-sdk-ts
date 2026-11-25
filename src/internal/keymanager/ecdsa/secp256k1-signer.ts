/**
 * secp256k1 recoverable 署名・検証・鍵導出・鍵復元の純粋関数モジュール（Ethereum 互換）。
 *
 * `../signer.ts` から責務分離した実装で、公開 API の入口は従来どおり `signer.ts` に一本化する
 * （利用側は本モジュールを直接 import せず `signer.ts` を経由する）。
 *
 * sign / recoverPublicKey は「すでにハッシュ済みのダイジェスト」を入力とする前提で、`@noble` の
 * 内部ハッシュ（既定 sha256）を無効化する `prehash: false` を必ず指定する。したがって `digest` は
 * 呼び出し側で計算済みの 32 バイトでなければならない。
 *
 * セキュリティ上の注意:
 * - privateKey / digest などの秘密・入力データは、例外メッセージや `context` に一切含めない。
 * - `@noble` 由来の例外は、メッセージに秘密が含まれ得るため `cause` を渡さず握りつぶす
 *   （`../signer.ts` の元実装と同様）。
 */

import { secp256k1 } from '@noble/curves/secp256k1.js';
import { ErrorCodes, VericertsError } from '../../errors.js';
import { ownProperty } from '../../prototype-safety/own-property.js';
import {
  assertDigest,
  DIGEST_LENGTH,
  type EcdsaSignatureEncoding,
  P1363_LENGTH,
  RECOVERED_LENGTH,
  type VerifySecp256k1Options,
  verifyEcdsaCanonical,
} from './signature-format.js';

/**
 * Ethereum 互換の recoverable 署名。
 *
 * `signature` は `r(32) || s(32) || recovery(1)` の 65 バイト。`recovery` は 0 または 1 で、
 * この値があれば署名とダイジェストのみから公開鍵を復元できる。
 */
export interface RecoverableSignature {
  /** 65 バイトの署名（r(32) || s(32) || recovery(1)）。 */
  readonly signature: Uint8Array;
  /** recovery id（0 または 1）。 */
  readonly recovery: number;
}

/**
 * secp256k1 で recoverable 署名を生成する（Ethereum 互換）。
 *
 * RFC6979 による決定論的署名（同一入力で同一署名）と low-s 正規化を行う。
 * 戻り値の `signature` は `r(32) || s(32) || recovery(1)` の 65 バイト。
 *
 * @param digest 署名対象のダイジェスト（32 バイト）。
 * @param privateKey 秘密鍵（32 バイト）。
 * @returns recovery id 付きの 65 バイト署名。
 * @throws privateKey が不正な場合（VericertsError、code `1003`）、
 *         digest 長不正・署名演算失敗の場合（VericertsError、code `1020`）。
 */
export function signSecp256k1Recoverable(
  digest: Uint8Array,
  privateKey: Uint8Array,
): RecoverableSignature {
  assertDigest(digest);
  if (!secp256k1.utils.isValidSecretKey(privateKey)) {
    throw new VericertsError(ErrorCodes.INVALID_PRIVATE_KEY);
  }
  let sig: ReturnType<(typeof secp256k1.Signature)['fromBytes']>;
  try {
    // prehash:false でダイジェスト入力。既定で lowS 正規化・RFC6979 決定論的。
    const recovered = secp256k1.sign(digest, privateKey, { prehash: false, format: 'recovered' });
    sig = secp256k1.Signature.fromBytes(recovered, 'recovered');
  } catch {
    // @noble 由来の例外メッセージに秘密が含まれ得るため cause は渡さない。
    throw new VericertsError(ErrorCodes.SIGN_FAILED);
  }
  // recovery は recoverable 署名では必ず付与される。型上の Optional をガードする。
  const recovery = sig.recovery;
  if (recovery === undefined) {
    throw new VericertsError(ErrorCodes.SIGN_FAILED);
  }
  // 公開フォーマット r||s||recovery(0/1) を組み立てる（@noble の 'recovered' バイト列とは別表現）。
  const compact = sig.toBytes('compact');
  const signature = new Uint8Array(RECOVERED_LENGTH);
  signature.set(compact, 0);
  signature[P1363_LENGTH] = recovery;
  return { signature, recovery };
}

/**
 * secp256k1 署名を検証する。
 *
 * 既定では **RFC 7515 §3.1 準拠の厳密 64 バイト `r || s`（`encoding: 'p1363'`）のみ**を受理し、
 * low-S を強制する。65 バイトへの末尾付加や DER 再エンコードといった非正準表現は拒否するため、
 * 同一メッセージ・同一鍵に対して有効な署名バイト列がただ一つに定まる（可鍛性の排除）。
 *
 * 非 JWS 用途（Ethereum 互換の recovery 付き署名、DER を返す HSM 等）は `options.encoding` で
 * 明示的に opt-in する。`'recovered'` では recovery バイトが実際に当該公開鍵を復元することまで
 * 検証するため、末尾 1 バイトを差し替えた署名は通らない。
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
export function verifySecp256k1(
  digest: Uint8Array,
  signature: Uint8Array,
  publicKey: Uint8Array,
  options: VerifySecp256k1Options = {},
): boolean {
  if (digest.length !== DIGEST_LENGTH) {
    return false;
  }
  return verifyEcdsaCanonical(
    secp256k1,
    digest,
    signature,
    publicKey,
    // 任意オプションは自身のプロパティに限って読む。`options.allowHighS ?? false` はプロトタイプ鎖を
    // 辿るため、`Object.prototype.allowHighS = true` の汚染下では**オプションを渡していない正当な
    // 検証でも high-S 署名が受理される**（可鍛性が復活し、署名バイト列を重複判定キーに使う経路の
    // リプレイ検知が壊れる）。`encoding` も同様に受理表現が厳密 64 バイト以外へ広がる。
    ownProperty<EcdsaSignatureEncoding>(options, 'encoding') ?? 'p1363',
    ownProperty<boolean>(options, 'allowHighS') ?? false,
  );
}

/**
 * secp256k1 秘密鍵から公開鍵を導出する。
 *
 * @param privateKey 秘密鍵（32 バイト）。
 * @param compressed 圧縮形式にするか（既定 `true` = 33 バイト、`false` = 65 バイト非圧縮）。
 * @returns 公開鍵バイト列。
 * @throws privateKey が不正な場合（VericertsError、code `1003`）。
 */
export function getSecp256k1PublicKey(privateKey: Uint8Array, compressed = true): Uint8Array {
  if (!secp256k1.utils.isValidSecretKey(privateKey)) {
    throw new VericertsError(ErrorCodes.INVALID_PRIVATE_KEY);
  }
  try {
    return secp256k1.getPublicKey(privateKey, compressed);
  } catch {
    throw new VericertsError(ErrorCodes.INVALID_PRIVATE_KEY);
  }
}

/**
 * secp256k1 の recoverable 署名から公開鍵を復元する。
 *
 * @param digest 署名時のダイジェスト（32 バイト）。
 * @param recoverable recoverable 署名（`r(32) || s(32) || recovery(1)` の 65 バイト）。
 * @param compressed 圧縮形式にするか（既定 `true` = 33 バイト、`false` = 65 バイト非圧縮）。
 * @returns 復元された公開鍵バイト列。
 * @throws digest 長不正・recoverable 形式不正・復元失敗の場合（VericertsError、code `1020`）。
 */
export function recoverSecp256k1PublicKey(
  digest: Uint8Array,
  recoverable: Uint8Array,
  compressed = true,
): Uint8Array {
  assertDigest(digest);
  if (recoverable.length !== RECOVERED_LENGTH) {
    throw new VericertsError(ErrorCodes.SIGN_FAILED);
  }
  try {
    // 公開フォーマット r||s||recovery(0/1) から Signature を再構築する。
    // @noble の 'recovered' バイト列は recovery を別表現で埋め込むため、compact + addRecoveryBit で組み直す。
    const compact = recoverable.subarray(0, P1363_LENGTH);
    const recovery = recoverable[P1363_LENGTH];
    if (recovery === undefined) {
      throw new VericertsError(ErrorCodes.SIGN_FAILED);
    }
    const sig = secp256k1.Signature.fromBytes(compact, 'compact').addRecoveryBit(recovery);
    return sig.recoverPublicKey(digest).toBytes(compressed);
  } catch (error) {
    // 自前で投げた VericertsError はそのまま伝播させる。
    if (error instanceof VericertsError) {
      throw error;
    }
    // @noble 由来の例外メッセージに秘密が含まれ得るため cause は渡さない。
    throw new VericertsError(ErrorCodes.SIGN_FAILED);
  }
}
