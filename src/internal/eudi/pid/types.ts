/**
 * EUDI PID (Personal Identification Data) / (Q)EAA の型定義。
 *
 * ARF PID Rulebook v1.5 の属性、(Q)EAA Catalogue と検証結果を表す。PID は `vct=urn:eudi:pid:1` で識別する。
 *
 * **ここには発行用の型が無い。** PID / (Q)EAA そのものを表す型（`PIDCredential` / `PIDClaims` /
 * `EAACredential` 等）はいずれも受領済みのものを表す。ほかに定義するものの主なものは、
 * 受領オプション型（`PIDReceiveOptions`）・スキーマ検証結果型（`SchemaError` /
 * `SchemaValidationResult` の再エクスポート）・(Q)EAA Catalogue 項目型
 * （`AttestationCatalogueEntry`）である。
 * `eudi/pid` が担うのは受領した PID / (Q)EAA の型定義とスキーマ検証・(Q)EAA Catalogue 参照だけで、
 * 発行 API も提示 API も持たず（発行 API は今後も持たせない）、
 * PID の発行は本 SDK のスコープ外である。発行主体は加盟国指定の PID Provider であり、
 * SDK の発行経路は PID 生データの属性名を `10607 GDPR_SPECIAL_CATEGORY_ISSUANCE` で拒否する。
 */

/** PID の VC Type URI（ARF v1.5、`urn:eudi:pid:1`）。 */
export const PID_VCT = 'urn:eudi:pid:1' as const;

/**
 * PID Rulebook の必須属性名 7 種。
 *
 * `validatePIDSchema` はこれら全属性の存在と型を検査する。
 */
export const PID_MANDATORY_ATTRIBUTES = [
  'family_name',
  'given_name',
  'birth_date',
  'issuance_date',
  'expiry_date',
  'issuing_authority',
  'issuing_country',
] as const;

/** PID 必須属性名の union 型。 */
export type PIDMandatoryAttributeName = (typeof PID_MANDATORY_ATTRIBUTES)[number];

/**
 * PID Rulebook が列挙する任意属性名。
 *
 * `age_over_NN` の年齢はテンプレートリテラル型で表現する。
 */
export const PID_OPTIONAL_ATTRIBUTES = [
  'age_in_years',
  'age_birth_year',
  'family_name_birth',
  'given_name_birth',
  'birth_place',
  'birth_country',
  'birth_state',
  'birth_city',
  'resident_address',
  'resident_country',
  'resident_state',
  'resident_city',
  'resident_postal_code',
  'gender',
  'nationality',
  'document_number',
  'administrative_number',
  'issuing_jurisdiction',
  'portrait',
] as const;

/** PID 任意属性名（`age_over_NN` を除く列挙分）の union 型。 */
export type PIDEnumeratedOptionalAttributeName = (typeof PID_OPTIONAL_ATTRIBUTES)[number];

/**
 * PID 属性名（`PIDAttributeName`）。
 *
 * 必須属性 + 列挙された任意属性 + `age_over_${number}`（年齢閾値超過 boolean）。
 */
export type PIDAttributeName =
  | PIDMandatoryAttributeName
  | PIDEnumeratedOptionalAttributeName
  | `age_over_${number}`;

/**
 * PID クレーム集合（`vct` を除いた属性 → 値のマップ）。
 *
 * SD-JWT VC の payload から `vct` / `cnf` / `status` 等の構造クレームを除いた
 * ユーザー属性部分に相当する。値の型は属性ごとに異なるため `unknown` とし、
 * 型・形式の検査は `validatePIDSchema`（`schema.ts`）で行う。
 */
export type PIDClaims = {
  readonly [K in PIDMandatoryAttributeName]?: string;
} & {
  readonly [K in PIDEnumeratedOptionalAttributeName]?: unknown;
} & {
  /** 年齢閾値超過属性（`age_over_18` 等）。 */
  readonly [key: `age_over_${number}`]: boolean | undefined;
};

/**
 * PID Credential（受領済み PID）。
 *
 * SD-JWT VC 形式（`vct=urn:eudi:pid:1`）で受領した PID を表す。
 * `raw` は元の SD-JWT VC コンパクト表現、`claims` は復元済みの属性集合。
 */
export interface PIDCredential {
  /** VC Type URI。常に `urn:eudi:pid:1`。 */
  readonly vct: typeof PID_VCT;
  /** 復元済みの PID 属性集合。 */
  readonly claims: PIDClaims;
  /** 元の SD-JWT VC コンパクト表現（`<JWT>~<Disclosure>...~[<KB-JWT>]`）。 */
  readonly raw?: string;
}

/** (Q)EAA Credential（受領済み (Q)EAA）。個別属性は `vct` で識別し Catalogue で解決する。 */
export interface EAACredential {
  /** VC Type URI（例: 学位・健康保険証・年齢証明等）。 */
  readonly vct: string;
  /** 復元済みのクレーム集合。 */
  readonly claims: Readonly<Record<string, unknown>>;
  /** 元の SD-JWT VC コンパクト表現。 */
  readonly raw?: string;
}

/**
 * 受領した Credential の Issuer 署名検証を差し替えるフック。
 *
 * 指定すると `Wallet` メソッド層の**既定検証（DID 解決 + SD-JWT 署名検証）を置換する**
 * （併用しない）。`iss` が HTTPS URL の Issuer など、DID 以外の鍵解決（`x5c` / ETSI TSL Trust
 * Anchor / JWT VC Issuer Metadata）が要る運用のための出口である。`VericertsError` 以外・`3010` の throw は
 * `3010`（`reason: 'received_credential_signature_invalid'`）へ正規化され、`3010` 以外の
 * `VericertsError` は元のコードのまま伝播する（フックは VC 本文・署名を例外に載せないこと）。
 *
 * 検証を意図的に省きたい場合は no-op（`() => {}`）を渡す。
 */
export type VerifyReceivedAttestation = (raw: string) => void | Promise<void>;

/** `receivePID` の受領オプション（`PIDReceiveOptions`）。 */
export interface PIDReceiveOptions {
  /** OID4VCI Token Request に Wallet Unit Attestation を添付するか（既定 false）。 */
  readonly walletAttestation?: boolean;
  /** Issuer 署名の既定検証を置換する検証フック（省略時は既定検証）。 */
  readonly verifyReceived?: VerifyReceivedAttestation;
}

/**
 * `receiveEAA` の受領オプション。
 *
 * (Q)EAA の受領には Wallet Unit Attestation の添付経路が無い（`receiveEAA` は WUA を付けない）
 * ため、`PIDReceiveOptions` と型を共有せず検証フックだけを持つ独立の型にする。共有すると
 * `walletAttestation: true` が受け付けられそうに見えて実際には無視される、という誤解を招く。
 */
export interface EAAReceiveOptions {
  /** Issuer 署名の既定検証を置換する検証フック（省略時は既定検証）。 */
  readonly verifyReceived?: VerifyReceivedAttestation;
}

/**
 * スキーマ検証の結果型（`SchemaError`、`SchemaValidationResult`）。
 *
 * PID Rulebook と VC JSON Schema の検証では同じ結果型を使う。各エラーの `required` は必須属性の違反かどうかを示す。
 */
export type { SchemaError, SchemaValidationResult } from '../../credential/json-schema/index.js';

/**
 * (Q)EAA Catalogue エントリ（`AttestationCatalogueEntry`）。
 *
 * `resolveAttestationCatalogue(vct)` が返す vct → スキーマ解決結果。
 */
export interface AttestationCatalogueEntry {
  /** VC Type URI（主キー）。 */
  readonly vct: string;
  /** Rulebook ドキュメント URL。 */
  readonly rulebookUrl: string;
  /** JSON Schema URL。 */
  readonly schemaUrl: string;
  /** 許可 Issuer DID 一覧（任意）。 */
  readonly issuerAllowList?: readonly string[];
  /** エントリのバージョン。 */
  readonly version: string;
}
