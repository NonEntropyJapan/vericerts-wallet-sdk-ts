/**
 * Credential Request の本文の組み立て。
 *
 * `oid4vci.ts` から切り出した送信側の本文生成層（同ファイルの 300 行上限を保つため）。形は 2 つ:
 *
 * - **OID4VCI 1.0 Final 形**（§8.2）: `credentialConfigurationId` 指定時。`{ credential_configuration_id,
 *   proofs: { jwt: [<jwt>] } }`。`format` / `credential_definition` / `proof` は 1.0 に無いので**送らない**。
 * - **旧 Draft 形**（既定）: `{ format, credential_definition, proof: { proof_type: 'jwt', jwt } }`。
 *
 * 2 つの形を**混在させない**。1.0 の Issuer は `proof`（単数）と `proofs` の併存を拒否し、旧 Draft の Issuer
 * は `format` 欠落を拒否する。どちらの形で送るかは呼び出し側が明示する（SDK は Issuer のバージョンを推測しない）。
 *
 * セキュリティ上の注意: 呼び出し側が渡すオブジェクトは `JSON.parse` を通らないため、`credentialConfigurationId`
 * は own 限定で読む（鎖読みだと、指定していない旧 Draft 呼び出しが `Object.prototype` の汚染値で 1.0 形へ化ける）。
 */

import { ErrorCodes, VericertsError } from '../../../errors.js';
import { isNonBlankString } from '../../../prototype-safety/non-empty-string.js';
import { ownProperty } from '../../../prototype-safety/own-property.js';
import { SD_JWT_VC_FORMATS } from '../../matcher.js';
import type { CredentialDefinition, CredentialProof } from '../oid4vci.js';

/** 本文の組み立てに使う入力（`RequestCredentialOptions` の部分集合）。 */
export interface CredentialRequestBodyInput {
  readonly format: string;
  readonly credentialDefinition: CredentialDefinition;
  readonly proofJwt: string;
}

/**
 * Credential Request の JSON 本文を返す。
 *
 * @param options `RequestCredentialOptions`（`credentialConfigurationId` だけ own 限定で読む）。
 * @param input 旧 Draft 形に必要な値と JWT Proof。
 * @throws `credentialConfigurationId` が指定されたが空文字・非文字列のとき `8020`（本文の組み立て前）。
 */
export function buildCredentialRequestBody(
  options: object,
  input: CredentialRequestBodyInput,
): string {
  const configurationId = ownProperty<unknown>(options, 'credentialConfigurationId');
  if (configurationId === undefined) {
    const proof: CredentialProof = { proof_type: 'jwt', jwt: input.proofJwt };
    // **SD-JWT VC は型を `vct` の 1 値で持つ**（旧 Draft 形。draft-13 Annex A.3）。OID4VCI 1.0 Final の
    // Credential Request は `credential_configuration_id` で伝え `vct` を持たないので、下の 1.0 形には載せない。
    // `credential_definition` は JWT-VC（`jwt_vc_json` 系）の形なので、SD-JWT VC では送らない。
    // 両方を送ると、片方だけを見る Issuer と両方を突き合わせる Issuer で解釈が割れる。
    // `vct` 未指定のときは従来どおり `credential_definition` を送る（呼び出し側の移行を待つ）。
    //
    // `vct` は**任意**プロパティなので own 限定で 1 回だけ読む（`own-property.ts`）。鎖読みだと、
    // `vct` を渡さない正当な JWT-VC / 旧 Draft 呼び出しが `Object.prototype` の汚染値を拾い、
    // SD-JWT VC format のときに攻撃者の指定した型で VC を要求してしまう。
    const vct = ownProperty<unknown>(options, 'vct');
    if (SD_JWT_VC_FORMATS.has(input.format) && isNonBlankString(vct)) {
      return JSON.stringify({ format: input.format, vct, proof });
    }
    return JSON.stringify({
      format: input.format,
      credential_definition: input.credentialDefinition,
      proof,
    });
  }
  if (!isNonBlankString(configurationId)) {
    throw new VericertsError(ErrorCodes.CREDENTIAL_REQUEST_FAILED, {
      context: { reason: 'invalid_credential_configuration_id' },
    });
  }
  return JSON.stringify({
    credential_configuration_id: configurationId,
    proofs: { jwt: [input.proofJwt] },
  });
}

/**
 * 受領依存の `credentialRequestVersion` を own 限定で読み、1.0 Final 形で送るかを返す。
 *
 * 未指定 / `'draft'` は旧 Draft 形（`false`）、`'1.0'` は 1.0 Final 形（`true`）。それ以外は `invalid()` が返す
 * 例外で fail-closed（形の取り違えで Issuer へ誤った形を送らない）。依存の不正コードは facade（8010）と
 * EUDI（8020）で異なるため、例外の生成は呼び出し側に任せる。
 */
export function readFinalCredentialRequest(deps: object, invalid: () => VericertsError): boolean {
  const version = ownProperty<unknown>(deps, 'credentialRequestVersion');
  if (version === undefined || version === 'draft') {
    return false;
  }
  if (version === '1.0') {
    return true;
  }
  throw invalid();
}
