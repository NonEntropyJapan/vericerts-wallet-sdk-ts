/**
 * OID4VP `direct_post.jwt` 応答（JWE 暗号化）の構築。
 *
 * 本モジュールは Verifier の `client_metadata` から応答暗号化パラメータ（`alg` / `enc` / 公開鍵）を
 * 解決し、`{ vp_token, presentation_submission?, state }` を JWE Compact へ暗号化して
 * `response` パラメータの値を組み立てる責務を担う。JWE の暗号演算そのものは `jwe.ts` に委譲する。
 *
 * `client_metadata` の参照フィールド（OID4VP §5.1 / JARM）:
 *
 * | フィールド                             | 用途                                             |
 * | -------------------------------------- | ------------------------------------------------ |
 * | `authorization_encrypted_response_alg`  | JWE `alg`（既定なし。未指定 / 未対応値は 8036）  |
 * | `authorization_encrypted_response_enc`  | JWE `enc`（未指定時は `A256GCM` を既定とする）   |
 * | `jwks.keys[]`                           | `use:"enc"` の EC 公開鍵                              |
 *
 * セキュリティ上の注意:
 * - VP Token・`state`・`nonce` を例外メッセージ・`context` に含めない。`context.reason` は
 *   秘密を含まない固定の識別子のみとする。
 * - `client_metadata` に `use:"enc"` 鍵が無い場合に平文 `direct_post` へフォールバックしない。
 *   Verifier が暗号化応答を要求している以上、失敗させる方が安全側に倒れる。
 */

import { p256 } from '@noble/curves/nist.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { ErrorCodes, VericertsError } from '../../errors.js';
import type { PublicKeyJwk } from '../../identity/did.js';
import { jwkToUncompressedPublicKey, SUPPORTED_EC_CRV } from '../../identity/jwt/jwk-key.js';
import { ownProperty } from '../../prototype-safety/own-property.js';
import {
  encryptJweCompact,
  JWE_ENC_A256GCM,
  type JweAlg,
  type JweEnc,
  SUPPORTED_JWE_ALGS,
  SUPPORTED_JWE_ENCS,
} from './jwe.js';

/** Verifier の `client_metadata`（未パースの生 JSON）。 */
export type ClientMetadata = Readonly<Record<string, unknown>>;

/** `client_metadata` から解決した応答暗号化パラメータ。 */
export interface ResponseEncryptionParams {
  /** JWE 鍵管理アルゴリズム。 */
  readonly alg: JweAlg;
  /** JWE コンテンツ暗号化アルゴリズム。 */
  readonly enc: JweEnc;
  /** 暗号化に用いる Verifier 公開鍵 JWK。 */
  readonly jwk: PublicKeyJwk;
  /** 選択した鍵の `kid`（存在する場合）。 */
  readonly kid?: string;
}

/** `direct_post.jwt` で暗号化する応答ペイロード。 */
export interface EncryptedResponsePayload {
  /** VP Token（単一なら文字列、複数なら文字列配列）。 */
  readonly vpToken: string | string[];
  /** リクエストの `state`（そのまま返却する）。 */
  readonly state: string;
  /** PEx v2 Presentation Submission（DCQL 提示では省略する）。 */
  readonly presentationSubmission?: Readonly<Record<string, unknown>>;
}

/** 未対応 / 解決不能な暗号化パラメータを 8036 に正規化する。 */
function unsupported(reason: string): VericertsError {
  return new VericertsError(ErrorCodes.VP_RESPONSE_ENCRYPTION_UNSUPPORTED, { context: { reason } });
}

/** `client_metadata.jwks.keys` を配列として取り出す。欠落・型不正は 8036。 */
function readJwks(metadata: ClientMetadata): readonly Readonly<Record<string, unknown>>[] {
  // `client_metadata` は Verifier 由来の生 JSON。`metadata.jwks` はプロトタイプ鎖を辿るため、
  // `Object.prototype.jwks` が汚染された環境では **Verifier が鍵を告知していない要求でも
  // 汚染値が受信者鍵として採用され、vp_token が攻撃者の鍵で暗号化される**。自身のプロパティ
  // に限って読み、告知が無ければ 8036 で失敗させる。
  const jwks = ownProperty<unknown>(metadata, 'jwks');
  if (typeof jwks !== 'object' || jwks === null) {
    throw unsupported('client_metadata_jwks_missing');
  }
  const keys = ownProperty<unknown>(jwks, 'keys');
  if (!Array.isArray(keys)) {
    throw unsupported('client_metadata_jwks_missing');
  }
  return keys.filter(
    (key): key is Record<string, unknown> => typeof key === 'object' && key !== null,
  );
}

/**
 * 鍵が応答暗号化に使えるか判定する。
 *
 * `use` が指定されている場合は `enc` であることを要求し（署名鍵の誤用防止）、`key_ops` が
 * 指定されている場合は鍵合意 / 暗号化用途を含むことを要求する。鍵側に `alg` があるときは
 * ネゴシエート済みの `alg` と一致することを要求する（alg confusion 防止）。
 */
function isUsableEncryptionKey(key: Readonly<Record<string, unknown>>, alg: JweAlg): boolean {
  // JWK のメンバはすべて自身のプロパティに限って読む。`key.kty` がプロトタイプ鎖を辿ると、
  // `Object.prototype.kty = 'EC'` の汚染下で **`kty` を持たない任意のオブジェクトが EC 公開鍵
  // として受理される**（alg confusion）。`use` / `key_ops` / `alg` も、継承値は Verifier の
  // 告知ではないため「未指定」として扱うのが正しい。
  if (ownProperty<unknown>(key, 'kty') !== 'EC') {
    return false;
  }
  const use = ownProperty<unknown>(key, 'use');
  if (use !== undefined && use !== 'enc') {
    return false;
  }
  const keyOps = ownProperty<unknown>(key, 'key_ops');
  if (
    Array.isArray(keyOps) &&
    !keyOps.some(
      (op) => op === 'deriveKey' || op === 'deriveBits' || op === 'encrypt' || op === 'wrapKey',
    )
  ) {
    return false;
  }
  const keyAlg = ownProperty<unknown>(key, 'alg');
  if (keyAlg !== undefined && keyAlg !== alg) {
    return false;
  }
  return isP256PublicKey(key);
}

/**
 * 鍵が ECDH-ES で実際に使える P-256 公開鍵か（`crv` / 座標形式 / 曲線上の点）。
 *
 * 同一 JWKS に ES384 用 P-384 鍵と P-256 鍵が併記される Verifier は一般的で、先頭の EC 鍵だけを
 * 確定すると後続の有効な P-256 鍵が試されず提示不能になる。選択段階で不適格鍵を
 * 読み飛ばし、`encryptJweCompact` と同じ判定（`ecdh.ts` の `recipientPublicKey`）に揃える。
 */
function isP256PublicKey(key: Readonly<Record<string, unknown>>): boolean {
  try {
    const raw = jwkToUncompressedPublicKey(key as PublicKeyJwk, {
      expectedCrv: SUPPORTED_EC_CRV,
      errorCode: ErrorCodes.INVALID_DID,
    });
    p256.Point.fromBytes(raw);
    return true;
  } catch {
    return false;
  }
}

/**
 * `client_metadata` から応答暗号化パラメータ（`alg` / `enc` / 公開鍵）を解決する。
 *
 * `authorization_encrypted_response_alg` は必須とする。Verifier が `direct_post.jwt` を要求しつつ
 * `alg` を告知していない場合、Wallet 側が既定値を推測すると Verifier が復号できない応答を
 * 送ってしまうため、推測せず 8036 で失敗させる。`enc` は JARM 既定に倣い `A256GCM` を補う。
 *
 * @param metadata Verifier の `client_metadata`（`request.ts` がパース済みの生 JSON）。
 * @returns 解決済みの暗号化パラメータ。
 * @throws `client_metadata` 欠落 / 未対応 `alg`・`enc` / 利用可能な `enc` 鍵が無い場合
 *         （VericertsError、code `8036`）。
 */
export function resolveResponseEncryption(
  metadata: ClientMetadata | undefined,
): ResponseEncryptionParams {
  if (metadata === undefined) {
    throw unsupported('client_metadata_missing');
  }
  // `alg` を推測しない不変条件（下の docstring）は、継承値を拾うと崩れる。Verifier が
  // `alg` を告知していない要求でも `Object.prototype` の汚染値が「告知された alg」に化けるため、
  // 自身のプロパティに限って読む。`enc` も同様（汚染値による content encryption の格下げを防ぐ）。
  const rawAlg = ownProperty<unknown>(metadata, 'authorization_encrypted_response_alg');
  if (typeof rawAlg !== 'string' || !SUPPORTED_JWE_ALGS.has(rawAlg)) {
    throw unsupported('unsupported_response_encryption_alg');
  }
  const rawEnc =
    ownProperty<unknown>(metadata, 'authorization_encrypted_response_enc') ?? JWE_ENC_A256GCM;
  if (typeof rawEnc !== 'string' || !SUPPORTED_JWE_ENCS.has(rawEnc)) {
    throw unsupported('unsupported_response_encryption_enc');
  }
  const alg = rawAlg as JweAlg;
  const jwk = readJwks(metadata).find((key) => isUsableEncryptionKey(key, alg));
  if (jwk === undefined) {
    throw unsupported('encryption_key_not_found');
  }
  const ownJwkKid = ownProperty<unknown>(jwk, 'kid');
  return {
    alg,
    enc: rawEnc as JweEnc,
    jwk,
    // `kid` は JWE protected header に載る。継承値を載せると攻撃者が選んだ鍵 ID が
    // Verifier 側の鍵解決を誤導するため、自身のプロパティに限って読む。
    ...(typeof ownJwkKid === 'string' ? { kid: ownJwkKid } : {}),
  };
}

/** 応答ペイロードを OID4VP のパラメータ名（snake_case）へ直列化する。 */
function serializePayload(payload: EncryptedResponsePayload): string {
  // 任意プロパティは自身のプロパティに限って読む。呼び出し側が「未指定ならプロパティ自体を
  // 生やさない」形で組み立てていても、ここで継承値を拾い直すと汚染値が JWE 平文（= Verifier
  // へ送る応答本文）に混入する。
  const presentationSubmission = ownProperty<unknown>(payload, 'presentationSubmission');
  return JSON.stringify({
    vp_token: payload.vpToken,
    state: payload.state,
    ...(presentationSubmission !== undefined
      ? { presentation_submission: presentationSubmission }
      : {}),
  });
}

/**
 * `direct_post.jwt` の `response` パラメータ値（JWE Compact）を構築する。
 *
 * `{ vp_token, presentation_submission?, state }` を
 * ペイロードとし、`apv = SHA-256(nonce)` / `apu = SHA-256(wallet_nonce)` を ECDH-ES の
 * PartyVInfo / PartyUInfo に含める。`wallet_nonce` が無い場合は `apu` を省略する
 * （RFC 7518 §4.6.2 の既定である空 PartyUInfo として Concat KDF に入力される）。
 *
 * @param params `resolveResponseEncryption` が解決した暗号化パラメータ。
 * @param payload 暗号化する応答ペイロード。
 * @param nonce リクエストの `nonce`（`apv` の導出元）。
 * @param walletNonce Wallet が生成した `wallet_nonce`（`apu` の導出元。任意）。
 * @returns JWE Compact Serialization 文字列。
 * @throws 鍵導出・暗号化演算に失敗した場合（VericertsError、code `8037`）。
 */
export function buildEncryptedResponse(
  params: ResponseEncryptionParams,
  payload: EncryptedResponsePayload,
  nonce: string,
  walletNonce?: string,
): Promise<string> {
  const encoder = new TextEncoder();
  // `kid` は任意プロパティ。継承値を拾うと攻撃者が選んだ鍵 ID が JWE protected header に載る。
  const kid = ownProperty<string>(params, 'kid');
  return encryptJweCompact(serializePayload(payload), params.jwk, {
    alg: params.alg,
    enc: params.enc,
    ...(kid !== undefined ? { kid } : {}),
    apv: sha256(encoder.encode(nonce)),
    ...(walletNonce !== undefined ? { apu: sha256(encoder.encode(walletNonce)) } : {}),
  });
}
