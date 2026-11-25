// 再帰・配列要素 Disclosure（RFC 9901 §4.2.1 / §4.2.2 / §4.2.6）のテストが共有するヘルパ。
// 実鍵のみを使い、モックは使わない。

import { base64urlnopad } from '@scure/base';
import { ErrorCodes, VericertsError } from '../../../../errors.js';
import { disclosureDigest } from '../../disclosure.js';
import { verifySdJwt } from '../../verify.js';
import { ISSUER_JWK, reissueWithPayload, VCT } from '../hardening/shared.js';

export { encodeDisclosure } from '../../disclosure.js';
export { ISSUER_JWK, reissueWithPayload, VCT };

/** 検証時刻（`iat` と同一。未来 `iat` の 4014 を避ける）。 */
export const NOW = 1_767_225_600;

/** 配列要素の Disclosure（2 要素 `[salt, value]`）。 */
export function arrayDisclosure(
  value: unknown,
  salt: string,
): { encoded: string; digest: string; ref: { '...': string } } {
  const encoded = base64urlnopad.encode(new TextEncoder().encode(JSON.stringify([salt, value])));
  const digest = disclosureDigest(encoded);
  return { encoded, digest, ref: { '...': digest } };
}

/** 任意 JSON 配列を Disclosure として直接エンコードする（不正形状の再現用）。 */
export function rawDisclosure(parts: readonly unknown[]): { encoded: string; digest: string } {
  const encoded = base64urlnopad.encode(new TextEncoder().encode(JSON.stringify(parts)));
  return { encoded, digest: disclosureDigest(encoded) };
}

/** `iat` / `vct` を補った payload を再署名し、検証して復元クレームを返す。 */
export function verifyClaims(
  payload: Record<string, unknown>,
  disclosures: readonly string[],
): Record<string, unknown> {
  const sdJwt = reissueWithPayload({ vct: VCT, iat: NOW, ...payload }, disclosures);
  return verifySdJwt(sdJwt, { issuerKey: ISSUER_JWK, nowSeconds: NOW }).claims;
}

/** 検証が 3010 で拒否されること。 */
export function expectRejected(
  payload: Record<string, unknown>,
  disclosures: readonly string[],
): void {
  const sdJwt = reissueWithPayload({ vct: VCT, iat: NOW, ...payload }, disclosures);
  let thrown: unknown;
  try {
    verifySdJwt(sdJwt, { issuerKey: ISSUER_JWK, nowSeconds: NOW });
  } catch (error) {
    thrown = error;
  }
  if (!(thrown instanceof VericertsError) || thrown.code !== ErrorCodes.SIG_INVALID) {
    throw new Error(`3010 で拒否されるべきだが ${String(thrown)} だった`);
  }
}
