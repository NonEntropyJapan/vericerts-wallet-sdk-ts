/**
 * Credential Request の `credential_definition.type` の決定。
 *
 * `receive.ts` から分離しているのはファイル行数上限（300 行）のため
 * （`credential/presentation/vc-assert.ts` と同じ理由）。
 */

import { isNonBlankString } from '../../../prototype-safety/non-empty-string.js';
import type { IssuerEndpoints } from '../../eudi/issuance/metadata.js';
import type { CredentialOffer } from '../offer/oid4vci-offer.js';
import { facadeFailure } from './deps.js';

/**
 * Offer の `credential_configuration_ids` は Issuer Metadata の `credential_configurations_supported`
 * を引く**キー**であり、VC の `type` 配列そのものとは限らない（多くの実装で両者は一致しない）。
 * `issuer.credentialDefinitionTypes` に解決済みの値があればそれを使い、無ければ従来どおり
 * `credential_configuration_ids[0]` を単一要素の `type` として送る（fail-closed にしない理由は
 * `credentialDefinitionTypes` の JSDoc を参照。不一致は Issuer 側が拒否するだけで実害が無い）。
 */
export function resolveCredentialDefinitionType(
  offer: CredentialOffer,
  issuer: IssuerEndpoints,
): readonly string[] {
  const configurationId = offer.credential_configuration_ids[0];
  // **多層防御。到達不能である。** `parseCredentialOffer` は `credential_configuration_ids` が
  // 非空の文字列配列であることを保証するため、`[0]` は常に非空文字列。TS の
  // `noUncheckedIndexedAccess` を満たすための型の絞り込み。
  if (!isNonBlankString(configurationId)) {
    throw facadeFailure('missing_configuration_id');
  }
  return issuer.credentialDefinitionTypes?.get(configurationId) ?? [configurationId];
}

/**
 * SD-JWT VC の Credential Request が送る `vct` を Issuer Metadata の告知から解決する。
 *
 * `credential_configuration_ids[0]` は Metadata を引くための**不透明なキー**であって VC の `vct` では
 * ないため、告知（`credential_configurations_supported[id].vct`）だけを根拠にする。告知が無ければ
 * `undefined` を返す（fail-closed にしない理由は {@link resolveCredentialDefinitionType} と同じ —
 * この値は認可・認証の判定に使われず、不一致は Issuer が拒否するだけである）。
 *
 * **倒す先は呼び出し側が決める。** ファサード `receiveCredential` は Issuer の OID4VCI の版を推測
 * できないので、告知が無ければ `vct` を送らず従来の `credential_definition` へ倒す（`vct` を解さない
 * 旧 Draft の Issuer を壊さないため）。EUDI 経路（`receivePIDCredential` / `receiveEAACredential`）は
 * ARF / HAIP が SD-JWT VC を必須にするので倒さず、告知が無ければ PID の固定 `vct` / Offer の
 * configuration id を使って**常に `vct` を送る**。この非対称は意図したもの。
 */
export function resolveCredentialVct(
  offer: CredentialOffer,
  issuer: IssuerEndpoints,
): string | undefined {
  const configurationId = offer.credential_configuration_ids[0];
  if (!isNonBlankString(configurationId)) {
    return undefined;
  }
  return issuer.credentialVcts?.get(configurationId);
}

/**
 * 1.0 Final 形（`credentialRequestVersion: '1.0'`）のときだけ Offer の `credential_configuration_ids[0]` を返す
 * 旧 Draft 形は `undefined`。id を取れないときに旧形へ黙って倒さず `8010` で落とす。
 */
export function resolveCredentialConfigurationId(
  offer: CredentialOffer,
  finalCredentialRequest: boolean,
): string | undefined {
  if (!finalCredentialRequest) {
    return undefined;
  }
  const configurationId = offer.credential_configuration_ids[0];
  if (!isNonBlankString(configurationId)) {
    throw facadeFailure('missing_configuration_id');
  }
  return configurationId;
}
