/**
 * Issuer Metadata の `credential_configurations_supported` から、要求対象の configuration id だけの
 * `credential_definition.type` / `format` を解決する。
 *
 * **走査量は入力の積にしない。** 解決対象の id（Offer 由来）と各 id の `type` 配列（Metadata 由来）は
 * どちらも攻撃者が件数・長さを選べる。以前は id ごとに `type` 全体を走査・コピーしていたため、
 * 件数 N × 長さ M の積で CPU を占有できた。ここでは (1) id 件数に上限を課して重複を 1 回にまとめ、
 * (2) `type` は件数・長さ・合計長を上限内に制限し、(3) 走査した要素数を 1 回の解決で共有する
 * {@link WorkMeter} に数える。上限超過の `type` は「解決できない」（未収載）として扱う。
 */

import {
  isBoundedStringList,
  newWorkMeter,
  spendWork,
  type WorkMeter,
} from '../../../primitives/bounded-input.js';
import {
  CREDENTIAL_CONFIGURATION_ID_LIMITS,
  CREDENTIAL_DEFINITION_TYPE_LIMITS,
  MAX_METADATA_TYPE_SCAN_UNITS,
} from '../../../primitives/oid4vci-input-limits.js';
import { isNonBlankString } from '../../../prototype-safety/non-empty-string.js';
import { ownProperty } from '../../../prototype-safety/own-property.js';

/**
 * 解決対象の id を重複排除して返す。件数が上限を超える入力（`parseCredentialOffer` を通らない直接呼び出し）は
 * 解決しない（`undefined`）。重複排除の前に件数で判定するため、同一 id を並べた巨大配列でも走査は 1 回で済む。
 */
function distinctIds(ids: readonly string[] | undefined): readonly string[] | undefined {
  if (ids === undefined || ids.length > CREDENTIAL_CONFIGURATION_ID_LIMITS.maxCount) {
    return undefined;
  }
  return [...new Set(ids)];
}

/**
 * `credential_configurations_supported`（OID4VCI 1.0 §11.2.3）から、指定された
 * credential configuration id だけの `credential_definition.type` を解決する。
 *
 * **fail-closed にしない。** 告知が無い / 形が不正 / 上限超過の id は Map にキーを持たないまま返す
 * （`IssuerEndpoints.credentialDefinitionTypes` の JSDoc を参照）。`credential_configurations_supported`
 * 自体は OID4VCI 1.0 §11.2.3 の必須メンバだが、告知しない実装が実在するため必須化すると
 * その実装との互換を壊す。要求対象の id だけを解決し、無関係な数十〜数百件のエントリを
 * 走査・保持しない（不要な信頼面の拡大を避ける）。
 *
 * @param parsed Metadata 文書（プロトタイプ除去済み）。
 * @param credentialConfigurationIds 解決対象の configuration id 群。未指定 / 空なら解決しない。
 * @param meter `type` の走査量の予算（テストが `spent` を pin するための注入口。省略時は 1 回の解決ごとに新規）。
 * @returns id → `type` 配列の Map。解決できた id が 1 件も無ければ `undefined`。
 */
export function resolveCredentialDefinitionTypes(
  parsed: object,
  credentialConfigurationIds: readonly string[] | undefined,
  meter: WorkMeter = newWorkMeter(MAX_METADATA_TYPE_SCAN_UNITS),
): ReadonlyMap<string, readonly string[]> | undefined {
  const ids = distinctIds(credentialConfigurationIds);
  if (ids === undefined || ids.length === 0) {
    return undefined;
  }
  const configs = ownProperty<unknown>(parsed, 'credential_configurations_supported');
  if (typeof configs !== 'object' || configs === null) {
    return undefined;
  }
  const resolved = new Map<string, readonly string[]>();
  for (const id of ids) {
    const entry = ownProperty<unknown>(configs, id);
    if (typeof entry !== 'object' || entry === null) {
      continue;
    }
    const definition = ownProperty<unknown>(entry, 'credential_definition');
    if (typeof definition !== 'object' || definition === null) {
      continue;
    }
    const type = ownProperty<unknown>(definition, 'type');
    if (!Array.isArray(type) || type.length === 0) {
      continue;
    }
    // 走査量を共有予算から先に引く（尽きていれば走査しない）。件数の上限は `isBoundedStringList` が
    // 要素へ触れる前に判定するので、巨大な `type` を 1 要素も読まずに捨てられる。
    if (
      type.length > CREDENTIAL_DEFINITION_TYPE_LIMITS.maxCount ||
      !spendWork(meter, type.length) ||
      !isBoundedStringList(type, CREDENTIAL_DEFINITION_TYPE_LIMITS, isNonBlankString)
    ) {
      continue;
    }
    resolved.set(id, [...type]);
  }
  return resolved.size === 0 ? undefined : resolved;
}

/**
 * 指定された credential configuration id だけについて、configuration 直下の**文字列メンバ**を解決する。
 *
 * `format` と `vct` で規則が同一（{@link resolveCredentialDefinitionTypes} と同じ。告知が無い /
 * 非文字列は未収載、1 件も解決できなければ `undefined`）なので、読む名前だけを引数にして 1 本に
 * まとめる。走査量は id の件数に比例し、`distinctIds` が上限を掛けている。
 */
function resolveStringMember(
  parsed: object,
  credentialConfigurationIds: readonly string[] | undefined,
  member: string,
): ReadonlyMap<string, string> | undefined {
  const configs = ownProperty<unknown>(parsed, 'credential_configurations_supported');
  const ids = distinctIds(credentialConfigurationIds);
  if (ids === undefined || typeof configs !== 'object' || configs === null) {
    return undefined;
  }
  const resolved = new Map<string, string>();
  for (const id of ids) {
    const entry = ownProperty<unknown>(configs, id);
    const value =
      typeof entry === 'object' && entry !== null ? ownProperty<unknown>(entry, member) : undefined;
    if (isNonBlankString(value)) {
      resolved.set(id, value);
    }
  }
  return resolved.size === 0 ? undefined : resolved;
}

/**
 * 指定された credential configuration id だけの `format` を解決する
 * （{@link resolveCredentialDefinitionTypes} と同じ規則。告知が無い / 非文字列は未収載）。
 */
export function resolveCredentialFormats(
  parsed: object,
  credentialConfigurationIds: readonly string[] | undefined,
): ReadonlyMap<string, string> | undefined {
  return resolveStringMember(parsed, credentialConfigurationIds, 'format');
}

/**
 * 指定された credential configuration id だけの `vct`（SD-JWT VC の型識別子）を解決する。
 *
 * SD-JWT VC の Credential Request は `credential_definition` ではなく `vct` で型を伝える
 * （旧 Draft 形。draft-13 Annex A.3。1.0 Final の Credential Request は `credential_configuration_id`
 * で伝え、`vct` は要求に無い）。その `vct` は Offer の configuration id ではなく
 * **Issuer が告知した値**でなければならない（id は Metadata を引くための不透明なキーにすぎず、
 * 実装によっては両者が一致しない。walt.id issuer-api は告知値と突き合わせて拒否する）。
 */
export function resolveCredentialVcts(
  parsed: object,
  credentialConfigurationIds: readonly string[] | undefined,
): ReadonlyMap<string, string> | undefined {
  return resolveStringMember(parsed, credentialConfigurationIds, 'vct');
}
