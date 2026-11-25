/**
 * JWT-VC（コンパクト JWS）として内包された VC 1 件の検証
 * （`credential-entry-verify.ts` から切り出し）。
 *
 * デコード → 発行者鍵の解決 → `verifyCredential` への委譲 → 提示者突合の順で評価し、
 * どの段の不成立も例外ではなく `valid: false` として返す（他の VC の結果を失わないため）。
 * 突合（`requireHolderBinding`）の判定自体は `holder-binding.ts` にある。
 */

import { ErrorCodes } from '../../../errors.js';
import type { VCFormat } from '../../format-negotiation/types.js';
import { decodeCompactJwsOrThrow } from '../../vc/jws.js';
import { verifyCredential } from '../../vc/verify.js';
import type { EmbeddedCredentialVerifyInput, VerificationResult } from '../credential-results.js';
import { credentialKeyOf, delegatedOptions, nowSecondsOf } from './entry-input.js';
import {
  codeOf,
  failed,
  isExpiredAt,
  issuerOf,
  jwtVcTypesOf,
  trustedIssuerResultOf,
  UNCHECKED,
} from './entry-result.js';
import { holderBindingErrorOf } from './holder-binding.js';

/** JWT-VC（コンパクト JWS）1 件を検証する。 */
export function verifyJwtVcEntry(
  jwt: string,
  index: number,
  input: EmbeddedCredentialVerifyInput,
): VerificationResult {
  // VP に内包された JWT-VC は `jwt_vc_json` と `jwt_vc_json-ld` を構造的に判別できない。両者は同じ
  // JWS Enveloping Proof で保護され、SD-JWT VC の `typ` のような自己申告ヘッダも持たない一方、SDK の
  // `VerifiableCredential` 型は `@context` を無条件に必須とするため本文も区別できない。ここで
  // `jwt_vc_json` に倒すのは受理済みの制約であり、この値は**診断専用**である: 検証の可否・失効判定の
  // いずれも SDK 内ではこのラベルで分岐しない（`VerificationResult.format` は `verify-result.ts` が
  // そのまま写すだけで、比較・分岐する箇所は SDK 内に無い）。唯一 `credentialKey` コールバック（DI）へ
  // 引き渡されるが、それは診断用の同定情報であり、JWT-VC 経路では常に同じ値なので呼び出し側にとっても
  // 分岐材料にならない。format ネゴシエーションのラベルが必要な
  // 経路（DCQL 照合）では、本文推定ではなく呼び出し側が明示する（`auth/matcher.ts` の
  // `toQueryableFromVc`）。
  const format: VCFormat = 'jwt_vc_json';
  let payload: Record<string, unknown>;
  try {
    payload = decodeCompactJwsOrThrow(jwt, ErrorCodes.SIG_INVALID).payload;
  } catch (error) {
    return failed(format, '', codeOf(error), input);
  }
  const issuerDID = issuerOf(payload);
  const types = jwtVcTypesOf(payload);
  const key = credentialKeyOf(input)?.({ entry: jwt, index, format, issuerDID });
  if (key === undefined) {
    // 鍵が無い = 署名を検証できない。未検証のまま成功にはしない（fail-closed）。
    return failed(format, issuerDID, ErrorCodes.SIG_INVALID, input, types);
  }
  try {
    verifyCredential(jwt, { key, ...delegatedOptions(input) });
  } catch (error) {
    return {
      valid: false,
      errors: [codeOf(error)],
      issuerDID,
      isExpired: isExpiredAt(payload, nowSecondsOf(input)),
      format,
      ...UNCHECKED,
      isTrustedIssuer: trustedIssuerResultOf(input, issuerDID, types),
    };
  }
  // 発行者署名・時刻が通ったうえで、提示者との突合（opt-in）を評価する。
  const bindingError = holderBindingErrorOf(payload, input);
  if (bindingError !== undefined) {
    return failed(format, issuerDID, bindingError, input, types);
  }
  return {
    valid: true,
    issuerDID,
    isExpired: false,
    format,
    ...UNCHECKED,
    isTrustedIssuer: trustedIssuerResultOf(input, issuerDID, types),
  };
}
