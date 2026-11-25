/**
 * DIDベース SIOPv2 の RP メタデータ検証（`client_metadata` / `registration`）。
 *
 * DIDベース SIOPv2 では、RP が `client_metadata`（標準。後方互換で `registration`）で「DID を subject として
 * 受理できる」ことと「Wallet が生成できる署名アルゴリズムを受理できる」ことを宣言している必要がある。
 * 宣言が無い・不整合な RP へ DID を含む ID Token を送っても RP 側で拒否されるため、送信前に fail-closed で
 * 検証する。両方あるときは `client_metadata` を使う。
 */

import { ErrorCodes, VericertsError } from '../../errors.js';
import { ownProperty } from '../../prototype-safety/own-property.js';
import type { RPRegistration, SIOPv2Request } from './types.js';
import { requestsVpToken } from './vp-token.js';

/** DID subject syntax type の判別に使う接頭辞（`did` 単独、または `did:` 始まりの値）。 */
const DID_SUBJECT_SYNTAX_TYPE = 'did';
const DID_SUBJECT_SYNTAX_PREFIX = 'did:';

/**
 * SIOPv2 Request の RP メタデータが DIDベース SIOPv2 の要件を満たすか検証する。
 *
 * @param request パース済み `SIOPv2Request`。
 * @param signerAlg ID Token（と VP Token）の署名に使う予定のアルゴリズム（`CredentialSigner.alg`）。
 * @returns 検証済みの `RPRegistration`（`client_metadata` があればそれ、無ければ `registration`）。
 * @throws RP メタデータ未指定・`subject_syntax_types_supported` が DID を含まない・
 *   `id_token_signing_alg_values_supported` が `signerAlg` を含まない・`id_token_signed_response_alg` が `signerAlg` と
 *   異なる・`vp_token` を要求するのに
 *   RP が宣言した `jwt_vp.alg_values` が `signerAlg` を含まない場合（VericertsError、code `4002`）。
 */
export function assertValidRPRegistration(
  request: SIOPv2Request,
  signerAlg: string,
): RPRegistration {
  // メタデータは own 限定（未提示の RP が `Object.prototype.registration` の汚染値で登録検査を通らない）。
  const registration =
    ownProperty<RPRegistration>(request, 'clientMetadata') ??
    ownProperty<RPRegistration>(request, 'registration');
  if (registration === undefined) {
    throw new VericertsError(ErrorCodes.RP_REGISTRATION_INVALID, {
      context: { reason: 'registration_missing' },
    });
  }

  const supportsDidSubject = registration.subjectSyntaxTypesSupported.some(
    (type) => type === DID_SUBJECT_SYNTAX_TYPE || type.startsWith(DID_SUBJECT_SYNTAX_PREFIX),
  );
  if (!supportsDidSubject) {
    throw new VericertsError(ErrorCodes.RP_REGISTRATION_INVALID, {
      context: { reason: 'subject_syntax_type_unsupported' },
    });
  }

  // 署名アルゴリズム: RP は複数形の `id_token_signing_alg_values_supported`（配列）か、標準の
  // `id_token_signed_response_alg`（単一）か、両方で宣言する。宣言されているものはすべて満たすこと。
  const algValues = ownProperty<readonly string[]>(
    registration,
    'idTokenSigningAlgValuesSupported',
  );
  const responseAlg = ownProperty<string>(registration, 'idTokenSignedResponseAlg');
  if (
    (algValues !== undefined && !algValues.includes(signerAlg)) ||
    (responseAlg !== undefined && responseAlg !== signerAlg)
  ) {
    throw new VericertsError(ErrorCodes.RP_REGISTRATION_INVALID, {
      context: { reason: 'signing_alg_unsupported' },
    });
  }

  // RP が JWT-VP の署名アルゴリズムを宣言しているときは、VP Token を返す要求でそれも満たすこと。
  const jwtVpAlgs = ownProperty<readonly string[]>(registration, 'jwtVpAlgValuesSupported');
  if (
    requestsVpToken(request.responseType) &&
    jwtVpAlgs !== undefined &&
    !jwtVpAlgs.includes(signerAlg)
  ) {
    throw new VericertsError(ErrorCodes.RP_REGISTRATION_INVALID, {
      context: { reason: 'vp_signing_alg_unsupported' },
    });
  }

  return registration;
}
