/**
 * Credential Request 用 DPoP proof の生成判定。
 *
 * `receiveCredential`（pre-authorized_code / authorization_code の両経路）と
 * `receiveCredentialViaAuthorizationCode` が同じ判定を使う。`token_type` の判定を経路ごとに
 * 書き写すと、片方だけ Bearer 束縛のトークンへ `Authorization: DPoP` を付けて拒否される
 * （pre-authorized 経路だけが直され、authorization_code 経路が取り残された）。
 *
 * - Token Response の `token_type` が `DPoP` のときだけ proof を作る。Bearer 束縛のトークンに
 *   `Authorization: DPoP` を付けると RFC 9449 §7.1 準拠の Issuer が拒否する。RFC 9449 §5 は
 *   Token Request に proof を添えても AS が `Bearer` を返すことを許す。
 * - proof には access_token の `ath`（RFC 9449 §4.2）を載せられるよう、`createDpopProof` の第 2 引数で
 *   access_token を渡す。PAR / Token 用の proof は従来どおり `htu` のみで呼ぶ
 *   （その時点では access_token が存在しない）。
 */

import type { DpopProof } from '../dpop/dpop-common.js';

/**
 * `createDpopProof` の第 2 引数。Credential Endpoint 用の呼び出しには access_token が、
 * `use_dpop_nonce` による再送時には nonce が渡される。
 *
 * @experimental 挙動・シグネチャが変わることがある（v1.0 で `@stable` 昇格予定）。
 */
export interface DpopProofContext {
  /**
   * Token Response で得た access_token。保護リソース（Credential Endpoint）へ提示する proof の
   * `ath` クレーム（`computeAth(accessToken)`）の算出元で、`createDpopProof({ htm, htu, accessToken }, signer)`
   * へそのまま中継する（RFC 9449 §4.2 / §7.1）。
   */
  readonly accessToken?: string;
  /**
   * 宛先サーバが `DPoP-Nonce` で要求した nonce（RFC 9449 §8 / §9）。proof の `nonce` クレームへ
   * `createDpopProof({ htm, htu, accessToken, nonce }, signer)` でそのまま中継する。
   * `use_dpop_nonce` を受けた**再送時にだけ**渡される（初回の proof は nonce なし）。
   */
  readonly nonce?: string;
}

/**
 * DPoP proof 生成関数（`htu` ごとに proof を作る。RFC 9449 §4.3）。
 *
 * @experimental 挙動・シグネチャが変わることがある（v1.0 で `@stable` 昇格予定）。
 */
export type DpopProofFactory = (htu: string, ctx?: DpopProofContext) => DpopProof;

/**
 * Credential Request に載せる DPoP proof を決める。
 *
 * @param tokenType Token Response の `token_type`（大文字小文字を区別しない。RFC 6749 §7.1）。
 * @param accessToken Token Response の `access_token`（proof の `ath` 用）。
 * @param credentialEndpoint Credential Endpoint（proof の `htu`）。
 * @param createDpopProof 呼び出し側の proof 生成関数。未指定なら `undefined`。
 * @returns DPoP 束縛トークンかつ生成関数ありのときだけ proof、それ以外は `undefined`
 *          （`Authorization: Bearer` で送られる）。
 */
export function credentialRequestDpop(
  tokenType: string,
  accessToken: string,
  credentialEndpoint: string,
  createDpopProof: DpopProofFactory | undefined,
): DpopProof | undefined {
  if (tokenType.toLowerCase() !== 'dpop') {
    return undefined;
  }
  return createDpopProof?.(credentialEndpoint, { accessToken });
}
