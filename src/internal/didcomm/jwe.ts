/**
 * DIDComm v2 メッセージ暗号化の JWE Compact Serialization プリミティブ。
 *
 * 準拠規格: RFC 7516（JWE）/
 * RFC 7518 §4.6（ECDH-ES）/ §5.3（A256GCM）/ RFC 3394（AES Key Wrap）。
 * 対応 `alg` は `ECDH-ES+A256KW` のみ、`enc` は `A256GCM` のみ。
 * 鍵合意の対応曲線は P-256 のみ（`auth/jwe/ecdh.ts` と同じ方針。DIDComm の keyAgreement 鍵は
 * `did:peer` numalgo2 の `.E` エレメントが P-256 / secp256k1 / Ed25519 いずれの Multikey も
 * 表現できるが、ECDH に使えるのは P-256 のみに限定する）。低レベルの暗号プリミティブ
 * （Concat KDF・ECDH-ES・AES-KW・AES-GCM）は `jwe-primitives.ts` に分離する（1 ファイル 300 行上限）。
 *
 * `auth/jwe/` と実装を共有しない理由: `auth/jwe/jwe.ts` は OID4VP `direct_post.jwt` 応答暗号化
 * 専用にスコープが文書化されており（暗号化方向のみ、復号を持たない）、DIDComm は受信メッセージの
 * 復号も必須である。低レベルアルゴリズムは同じ RFC 準拠のため類似実装になるが、依存を持ち込むより
 * 自己完結させる（`wallet-migration/kdf/backup-ecdh.ts` も同じ理由で独自の ECDH 実装を持つ）。
 *
 * DIDComm v2 の Authcrypt（JWS 署名 → JWE 暗号化）/ Anoncrypt（JWE 暗号化のみ）は、JWE protected
 * header の `cty`（content type）で内側のペイロードが JWS か平文 JSON かを区別する
 * （`didcomm/pack.ts` が使う）。
 *
 * セキュリティ上の注意:
 * - 例外メッセージ・`context` に鍵素材・平文・DID 文字列を含めない。
 */

import { p256 } from '@noble/curves/nist.js';
import { base64urlnopad } from '@scure/base';
import { isPlainObject } from '../credential/object-guards.js';
import { ErrorCodes, VericertsError } from '../errors.js';
import type { PublicKeyJwk } from '../identity/did.js';
import { toEpkJwk } from '../identity/jwt/epk-jwk.js';
import { ownProperty } from '../prototype-safety/own-property.js';
import { parseJsonWithoutPrototype } from '../prototype-safety/parse-json.js';
import {
  concatKdf,
  decryptContent,
  deriveSharedSecret,
  encryptContent,
  IV_LENGTH,
  KEY_LENGTH,
  publicKeyBytesFromJwk,
  TAG_LENGTH,
  unwrapCek,
  wrapCek,
} from './jwe-primitives.js';

/** DIDComm v2 が対応する JWE 鍵管理アルゴリズム。 */
export const DIDCOMM_JWE_ALG = 'ECDH-ES+A256KW' as const;
/** DIDComm v2 が対応する JWE コンテンツ暗号化アルゴリズム。 */
export const DIDCOMM_JWE_ENC = 'A256GCM' as const;
/** Anoncrypt（署名なし平文メッセージ）の内側ペイロード content type。 */
export const DIDCOMM_PLAIN_CTY = 'application/didcomm-plain+json' as const;
/** Authcrypt（送信者 JWS 署名済みメッセージ）の内側ペイロード content type。 */
export const DIDCOMM_SIGNED_CTY = 'application/didcomm-signed+json' as const;

/** JWE 暗号化パラメータ（受信者 `kid` と内側ペイロードの `cty`。いずれも protected header に載る）。 */
export interface DidCommJweEncryptParams {
  readonly kid?: string;
  readonly cty?: string;
}

/** JWE 復号結果（平文と protected header から読み取った `cty` / `kid`）。 */
export interface DidCommJweDecryptResult {
  readonly plaintext: string;
  readonly cty?: string;
  readonly kid?: string;
}

/**
 * 平文を JWE Compact Serialization へ暗号化する（`ECDH-ES+A256KW` / `A256GCM`）。
 *
 * @param plaintext 暗号化対象（Anoncrypt なら平文 JSON 文字列、Authcrypt なら送信者 JWS 文字列）。
 * @param recipientJwk 受信者の keyAgreement 公開鍵 JWK（`crv: P-256` のみ対応）。
 * @param params `kid` / `cty`（いずれも省略可）。
 * @returns JWE Compact Serialization 文字列。
 * @throws 受信者鍵が P-256 でない等パッキング前段の不整合（`DIDCOMM_PACKING_FAILED`。
 *         `resolve.ts` 側で検出済みのため通常ここには来ない）、暗号化処理自体の失敗
 *         （`DIDCOMM_PACK_FAILED`）。
 */
export async function encryptDidCommJwe(
  plaintext: string,
  recipientJwk: PublicKeyJwk,
  params?: DidCommJweEncryptParams,
): Promise<string> {
  const recipient = publicKeyBytesFromJwk(recipientJwk, ErrorCodes.DIDCOMM_PACKING_FAILED);
  let ephemeralSecret: Uint8Array;
  let ephemeralPublic: Uint8Array;
  try {
    ephemeralSecret = p256.utils.randomSecretKey();
    ephemeralPublic = p256.getPublicKey(ephemeralSecret, false);
  } catch {
    throw new VericertsError(ErrorCodes.DIDCOMM_PACK_FAILED);
  }
  const sharedSecret = deriveSharedSecret(
    ephemeralSecret,
    recipient,
    ErrorCodes.DIDCOMM_PACK_FAILED,
  );
  const derived = concatKdf(sharedSecret, DIDCOMM_JWE_ALG);
  const cek = crypto.getRandomValues(new Uint8Array(KEY_LENGTH));
  const encryptedKey = await wrapCek(derived, cek);

  // 任意プロパティは自身のプロパティに限って読む（`params` は
  // 呼び出し側供給のプレーンオブジェクト）。
  const kid = params === undefined ? undefined : ownProperty<string>(params, 'kid');
  const cty = params === undefined ? undefined : ownProperty<string>(params, 'cty');
  const header: Record<string, unknown> = {
    alg: DIDCOMM_JWE_ALG,
    enc: DIDCOMM_JWE_ENC,
    epk: toEpkJwk(ephemeralPublic),
    ...(kid !== undefined ? { kid } : {}),
    ...(cty !== undefined ? { cty } : {}),
  };
  const protectedHeader = base64urlnopad.encode(new TextEncoder().encode(JSON.stringify(header)));

  const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));
  const { ciphertext, tag } = await encryptContent(
    cek,
    iv,
    new TextEncoder().encode(plaintext),
    new TextEncoder().encode(protectedHeader),
  );

  return [
    protectedHeader,
    base64urlnopad.encode(encryptedKey),
    base64urlnopad.encode(iv),
    base64urlnopad.encode(ciphertext),
    base64urlnopad.encode(tag),
  ].join('.');
}

function parseEpkJwk(epk: unknown): PublicKeyJwk {
  if (typeof epk !== 'object' || epk === null) {
    throw new VericertsError(ErrorCodes.DIDCOMM_UNPACKING_FAILED);
  }
  return epk as PublicKeyJwk;
}

/**
 * JWE Compact Serialization を復号する。
 *
 * @param jwe JWE Compact Serialization 文字列。
 * @param myPrivateKey 自分の keyAgreement 秘密鍵（P-256、32 バイト raw scalar）。
 * @returns 平文と protected header の `cty` / `kid`。
 * @throws 構造不正（セグメント数不正・base64url 不正・`alg`/`enc` 非対応・`epk` 欠落）の場合
 *         `DIDCOMM_UNPACKING_FAILED`。鍵不一致による復号失敗（AES Key Wrap アンラップ失敗・
 *         GCM 認証タグ不一致）の場合 `DIDCOMM_UNPACK_FAILED`。
 */
export async function decryptDidCommJwe(
  jwe: string,
  myPrivateKey: Uint8Array,
): Promise<DidCommJweDecryptResult> {
  const parts = jwe.split('.');
  if (parts.length !== 5) {
    throw new VericertsError(ErrorCodes.DIDCOMM_UNPACKING_FAILED);
  }
  const [protectedHeaderSeg, encryptedKeySeg, ivSeg, ciphertextSeg, tagSeg] = parts as [
    string,
    string,
    string,
    string,
    string,
  ];

  let header: Record<string, unknown>;
  let encryptedKey: Uint8Array;
  let iv: Uint8Array;
  let ciphertext: Uint8Array;
  let tag: Uint8Array;
  try {
    const parsed = parseJsonWithoutPrototype(
      new TextDecoder().decode(base64urlnopad.decode(protectedHeaderSeg)),
    );
    // `null` / 配列 / プリミティブの protected header は `header.alg` で素の TypeError になる。
    if (!isPlainObject(parsed)) {
      throw new VericertsError(ErrorCodes.DIDCOMM_UNPACKING_FAILED);
    }
    header = parsed;
    encryptedKey = base64urlnopad.decode(encryptedKeySeg);
    iv = base64urlnopad.decode(ivSeg);
    ciphertext = base64urlnopad.decode(ciphertextSeg);
    tag = base64urlnopad.decode(tagSeg);
  } catch {
    throw new VericertsError(ErrorCodes.DIDCOMM_UNPACKING_FAILED);
  }
  if (
    ownProperty<unknown>(header, 'alg') !== DIDCOMM_JWE_ALG ||
    ownProperty<unknown>(header, 'enc') !== DIDCOMM_JWE_ENC
  ) {
    throw new VericertsError(ErrorCodes.DIDCOMM_UNPACKING_FAILED);
  }
  if (tag.length !== TAG_LENGTH) {
    throw new VericertsError(ErrorCodes.DIDCOMM_UNPACKING_FAILED);
  }

  const epkJwk = parseEpkJwk(ownProperty<unknown>(header, 'epk'));
  const senderEpkBytes = publicKeyBytesFromJwk(epkJwk, ErrorCodes.DIDCOMM_UNPACKING_FAILED);
  const sharedSecret = deriveSharedSecret(
    myPrivateKey,
    senderEpkBytes,
    ErrorCodes.DIDCOMM_UNPACK_FAILED,
  );
  const derived = concatKdf(sharedSecret, DIDCOMM_JWE_ALG);
  const cek = await unwrapCek(derived, encryptedKey);
  const plaintextBytes = await decryptContent(
    cek,
    iv,
    ciphertext,
    tag,
    new TextEncoder().encode(protectedHeaderSeg),
  );

  const ctyValue = ownProperty<unknown>(header, 'cty');
  const kidValue = ownProperty<unknown>(header, 'kid');
  return {
    plaintext: new TextDecoder().decode(plaintextBytes),
    cty: typeof ctyValue === 'string' ? ctyValue : undefined,
    kid: typeof kidValue === 'string' ? kidValue : undefined,
  };
}
