/**
 * SD-JWT VC として内包された VC 1 件の検証（`credential-entry-verify.ts` から切り出し）。
 *
 * 提示部のデコード → 実効バインド値のガード → 発行者鍵の解決 → `verifySdJwt` への委譲の順で
 * 評価する。突合は JWT-VC の `sub` 比較ではなく `requireKeyBinding: true` による `cnf` + KB-JWT の
 * 検証で行うため、失敗コードは委譲先の面がそのまま出る（未来 `iat` のスキュー超過など時刻系は
 * `4014`）。事前ガード（`hasEffectiveBinding`）は `holder-binding.ts` にある。
 */

import { ErrorCodes } from '../../../errors.js';
import type { PublicKeyJwk } from '../../../identity/did.js';
import { nonObjectPrototypeProperty, ownProperty } from '../../../prototype-safety/own-property.js';
import { SD_JWT_VC_TYP } from '../../sdjwt/typ.js';
import { verifySdJwt } from '../../sdjwt/verify.js';
import { decodeCompactJwsOrThrow } from '../../vc/jws.js';
import type { EmbeddedCredentialVerifyInput, VerificationResult } from '../credential-results.js';
import { credentialKeyOf, delegatedOptions, nowSecondsOf } from './entry-input.js';
import {
  codeOf,
  failed,
  isExpiredAt,
  issuerOf,
  sdJwtFormatOf,
  sdJwtVcTypesOf,
  trustedIssuerResultOf,
  UNCHECKED,
} from './entry-result.js';
import { hasEffectiveBinding } from './holder-binding.js';

/**
 * SD-JWT VC 1 件を検証する。
 *
 * `verifySdJwt` の `issuerKey` は `PublicKeyJwk` 固定なので、`credentialKey` が `{ verify }` 形式
 * （KMS / HSM へ委譲する検証コールバック）を返した SD-JWT は検証できず `3010` で fail-closed に
 * なる。
 *
 * KB-JWT が証明するのは `cnf.jwk` の**鍵保持**までで、その鍵と `vp.holder` DID の同一性までは
 * 含まない（DID Document との突合は本経路では行わない）。
 *
 * `requireHolderBinding: true` で実効 `audience` / `nonce` が欠けている場合は、KB-JWT を検証しても
 * 「この提示宛か」を判定できないため `3012` で fail-closed にする（`hasEffectiveBinding`）。
 */
export function verifySdJwtVcEntry(
  sdJwt: string,
  index: number,
  input: EmbeddedCredentialVerifyInput,
): VerificationResult {
  let header: Record<string, unknown>;
  let payload: Record<string, unknown>;
  try {
    const decoded = decodeCompactJwsOrThrow(
      sdJwt.slice(0, sdJwt.indexOf('~')),
      ErrorCodes.SIG_INVALID,
    );
    header = decoded.header;
    payload = decoded.payload;
  } catch (error) {
    return failed(SD_JWT_VC_TYP, '', codeOf(error), input);
  }
  const format = sdJwtFormatOf(header);
  const issuerDID = issuerOf(payload);
  const types = sdJwtVcTypesOf(payload);
  if (!hasEffectiveBinding(input)) {
    // 突合を要求されたのに、照合できる実効バインド値が無い。委譲先の `verifySdJwt` /
    // `assertKeyBinding` は `expectedAudience` / `expectedNonce` が `undefined` のとき照合を
    // **丸ごとスキップ**するため、ここを通すと KB-JWT の鍵保持だけを確かめて「提示者のもの」と
    // 報告することになる。`allowUnbound: true` + `requireHolderBinding: true` で
    // `expectedAudience` / `expectedNonce` を省略した呼び出しがまさにこれで、
    // **別 Verifier 宛・別セッション nonce の KB-JWT が `valid: true` で受理されていた**
    // 照合できない入力は fail-closed で拒否する。
    return failed(format, issuerDID, ErrorCodes.HOLDER_BIND_MISMATCH, input, types);
  }
  const key = credentialKeyOf(input)?.({ entry: sdJwt, index, format, issuerDID });
  // `key` はクラスインスタンスであり得るため own 限定では読まない（`Object.prototype` 由来だけ弾く）。
  const issuerKey =
    key === undefined || key === null || typeof key !== 'object'
      ? undefined
      : nonObjectPrototypeProperty<PublicKeyJwk>(key, 'publicKeyJwk');
  if (issuerKey === undefined) {
    return failed(format, issuerDID, ErrorCodes.SIG_INVALID, input, types);
  }
  try {
    verifySdJwt(sdJwt, {
      issuerKey,
      ...delegatedOptions(input),
      // OID4VP の実効 aud / nonce を KB-JWT 検証へ中継する。中継しないと、
      // `cnf` を持つ内包 SD-JWT VC に付いた KB-JWT が**別の Verifier / 別セッション宛でも素通り**する。
      // `delegatedOptions` と同じくキーは常に生やす（落とすと委譲先の own 読みが継承値を拾う）。
      audience: ownProperty<string>(input, 'audience'),
      nonce: ownProperty<string>(input, 'nonce'),
      // 突合を要求されたときだけ `cnf` + KB-JWT を必須にする。`cnf` を持たない bearer な
      // SD-JWT VC はここで 3012 になる（既定 false 時は従来どおり受理）。
      requireKeyBinding: ownProperty<boolean>(input, 'requireHolderBinding'),
    });
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
  return {
    valid: true,
    issuerDID,
    isExpired: false,
    format,
    ...UNCHECKED,
    isTrustedIssuer: trustedIssuerResultOf(input, issuerDID, types),
  };
}
