/**
 * OID4VCI Authorization Code Flow の PKCE（RFC 7636, S256）生成。
 *
 * SDK の Authorization Code Flow は PKCE を必須とし方式を S256 に限定する。code_challenge は PAR（`par/par.ts`）で
 * push し、code_verifier は Token Request（`oid4vci-token.ts`）で送るため、生成部は双方から
 * 参照される。Token Endpoint への HTTP 呼び出しとは独立した純粋な値生成であり、モジュールを
 * 分けて責務を 1 つに保つ。
 *
 * セキュリティ上の注意:
 * - code_verifier は秘密であり、例外メッセージや `context` に含めない。
 */

import { sha256 } from '@noble/hashes/sha2.js';
import { base64urlnopad } from '@scure/base';
import { ErrorCodes, VericertsError } from '../../errors.js';

/** PKCE code_verifier の最小長（RFC 7636 §4.1）。 */
const PKCE_VERIFIER_MIN_LENGTH = 43;
/** PKCE code_verifier の最大長（RFC 7636 §4.1）。 */
const PKCE_VERIFIER_MAX_LENGTH = 128;
/**
 * `generatePkcePair` が生成する code_verifier のエントロピーバイト数。
 *
 * 32 バイトを base64url（パディングなし）化すると 43 文字となり、RFC 7636 の下限
 * （43 文字）を満たしつつ上限（128 文字）に収まる。
 */
const PKCE_VERIFIER_ENTROPY_BYTES = 32;

/** PKCE の code_verifier / code_challenge ペア（RFC 7636 S256）。 */
export interface PkcePair {
  /** ランダムな code_verifier（43〜128 文字、base64url）。Token Request まで保持し送信後に破棄する。 */
  readonly codeVerifier: string;
  /** `BASE64URL(SHA256(code_verifier))`。認可リクエストに含める。 */
  readonly codeChallenge: string;
  /** code_challenge_method。本 SDK は S256 のみを生成する。 */
  readonly codeChallengeMethod: 'S256';
}

/**
 * PKCE（RFC 7636, S256）の code_verifier / code_challenge ペアを生成する。
 *
 * `crypto.getRandomValues` で 32 バイトのエントロピーを取り、base64url（パディングなし）化した
 * code_verifier（43 文字）と、その SHA-256 を base64url 化した code_challenge を返す。
 * 認可リクエストに code_challenge / `code_challenge_method=S256` を載せ、Token Request に
 * code_verifier を載せる。
 *
 * @returns PKCE の code_verifier / code_challenge / method。
 */
export function generatePkcePair(): PkcePair {
  const entropy = new Uint8Array(PKCE_VERIFIER_ENTROPY_BYTES);
  crypto.getRandomValues(entropy);
  const codeVerifier = base64urlnopad.encode(entropy);
  // 設計上 43 文字に収まるが、定数変更時の不変条件として長さを検証する。
  if (
    codeVerifier.length < PKCE_VERIFIER_MIN_LENGTH ||
    codeVerifier.length > PKCE_VERIFIER_MAX_LENGTH
  ) {
    // code_verifier は秘密のため message / cause に含めない。
    throw new VericertsError(ErrorCodes.UNSUPPORTED_ALGORITHM);
  }
  const challengeBytes = sha256(new TextEncoder().encode(codeVerifier));
  const codeChallenge = base64urlnopad.encode(challengeBytes);
  return { codeVerifier, codeChallenge, codeChallengeMethod: 'S256' };
}
