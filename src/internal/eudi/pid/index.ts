/**
 * eudi/pid モジュールの公開エントリ。
 *
 * PID Rulebook 型定義・スキーマ検証・(Q)EAA Catalogue 参照を再エクスポートする。
 * これらは `exports/eudi.ts` から公開済みである。
 *
 * PID の発行主体は加盟国指定の PID Provider。`family_name` / `given_name` / `birth_date` / `birth_place` は SDK の発行経路では `10607 GDPR_SPECIAL_CATEGORY_ISSUANCE` で拒否する。
 * このチェックは受領・提示には適用しない。
 */

export {
  type AttestationCatalogueSource,
  createRecordCatalogueSource,
  resolveAttestationCatalogue,
} from './catalogue.js';
export { validatePIDClaims, validatePIDSchema } from './schema.js';
export {
  type AttestationCatalogueEntry,
  type EAACredential,
  type EAAReceiveOptions,
  PID_MANDATORY_ATTRIBUTES,
  PID_OPTIONAL_ATTRIBUTES,
  PID_VCT,
  type PIDAttributeName,
  type PIDClaims,
  type PIDCredential,
  type PIDEnumeratedOptionalAttributeName,
  type PIDMandatoryAttributeName,
  type PIDReceiveOptions,
  type SchemaError,
  type SchemaValidationResult,
  type VerifyReceivedAttestation,
} from './types.js';
