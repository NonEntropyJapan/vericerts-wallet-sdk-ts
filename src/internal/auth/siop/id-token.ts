/**
 * DIDベース SIOPv2 自己発行 ID Token の生成。
 *
 * `src/internal/eudi/pseudonym/siop.ts` の `presentPseudonym` と異なり、`sub` は
 * Pseudonym 派生鍵のハッシュではなく Holder の DID そのものになる。DID の解決・署名鍵の入手は
 * 呼び出し側（wallet 層）の責務とし、本モジュールは受け取った DID と署名鍵で ID Token を
 * 組み立てて署名するだけの純粋関数として実装する。
 *
 * セキュリティ上の注意: 例外メッセージ・`context` に privateKey・
 * JWT 本文を含めない。
 */

import { signCompactJwsAsync } from '../../credential/vc/compact-jws.js';
import type { CredentialSignerAlg } from '../../credential/vc/jws.js';
import { type AnyCredentialSigner, buildJwsHeader } from '../../credential/vc/signer.js';
import { ErrorCodes, VericertsError } from '../../errors.js';
import { isEpochSeconds, isLifetimeSeconds } from '../../primitives/option-guard.js';
import { ownProperty } from '../../prototype-safety/own-property.js';
import type { SIOPv2Request } from './types.js';

/** ID Token の既定有効期間（秒）。5 分（`presentPseudonym` と同じ既定値）。 */
const DEFAULT_ID_TOKEN_LIFETIME_SECONDS = 5 * 60;

/** `generateIDToken` のオプション。 */
export interface GenerateIdTokenOptions {
  /** 発行時刻（NumericDate、秒）。テスト・決定性のため注入する。 */
  readonly nowSeconds: number;
  /** ID Token の有効期間（秒）。既定は 5 分。 */
  readonly lifetimeSeconds?: number;
}

/**
 * DIDベース SIOPv2 の自己発行 ID Token を生成する。
 *
 * `iss` と `sub` は同値の Holder の DID（SIOPv2 draft 13「Self-Issued ID Token」。RP は `iss === sub` で
 * self-issued と判定し、`sub_jwk` で署名検証する。旧ドラフトの固定値 `https://self-issued.me/v2` は
 * `iss !== sub` となり準拠 RP に通常の OIDC として扱われ拒否される）。`aud` は要求の `client_id`、
 * `nonce` は要求の `nonce`
 *
 * @param request パース済み・RP 登録情報を検証済みの `SIOPv2Request`。
 * @param did ID Token の `sub` に載せる Holder の DID。
 * @param signer DID の秘密鍵に対応する署名鍵。
 * @param opts 発行オプション（`nowSeconds` / `lifetimeSeconds`）。
 * @returns 署名済みコンパクト JWS（ID Token）。
 * @throws `nowSeconds` が有限の非負エポック秒でない、または `lifetimeSeconds` が正の有限数でない場合
 *         （VericertsError、code `10201`。`iat` / `exp` が `null` や過去の署名済み ID Token を作らない）。
 */
export async function generateIDToken(
  request: SIOPv2Request,
  did: string,
  signer: AnyCredentialSigner<CredentialSignerAlg>,
  opts: GenerateIdTokenOptions,
): Promise<string> {
  const lifetime =
    ownProperty<number>(opts, 'lifetimeSeconds') ?? DEFAULT_ID_TOKEN_LIFETIME_SECONDS;
  if (!isEpochSeconds(opts.nowSeconds) || !isLifetimeSeconds(opts.nowSeconds, lifetime)) {
    throw new VericertsError(ErrorCodes.RP_IDENTIFIER_INVALID);
  }
  const claims = {
    iss: did,
    sub: did,
    aud: request.clientId,
    nonce: request.nonce,
    iat: opts.nowSeconds,
    exp: opts.nowSeconds + lifetime,
    // SIOPv2: RP が自己発行 ID Token を検証するための subject 鍵。
    sub_jwk: signer.publicKeyJwk,
  };
  return signCompactJwsAsync(buildJwsHeader(signer, 'JWT'), claims, signer);
}
