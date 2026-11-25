/**
 * 5xxx Trust / 10xxx EUDI のエラーコード定数（schemas/error-codes.json）。
 *
 * `errors.ts` の `ErrorCodes` に結合される部分定数。値は数値文字列。
 */

/** 5xxx（trust）/ 10xxx（eudi）のコード（数値文字列）。 */
export const TRUST_EUDI_ERROR_CODES = {
  /** PID Rulebook スキーマ違反（`validatePIDSchema` / `receivePID` で属性の型・形式が不正、10001）。Issuer 不正が主因のため再試行不可。 */
  PID_SCHEMA_INVALID: '10001',
  /** PID Rulebook 必須属性欠落（`validatePIDSchema` / `receivePID`、10002）。Issuer 不正 / 入力欠落が主因のため再試行不可。 */
  PID_REQUIRED_ATTR_MISSING: '10002',
  /** (Q)EAA Catalogue 未登録（`receiveEAA` / `resolveAttestationCatalogue` で vct がカタログ未掲載、10003）。カタログ登録が必要なため再試行不可。 */
  EAA_CATALOGUE_NOT_FOUND: '10003',
  /** WUA 取得失敗（`obtainWalletAttestation` で Wallet Provider Backend 応答エラー、10101）。ネットワーク/Provider 要因のため再試行可能。 */
  WUA_FETCH_FAILED: '10101',
  /** WUA 検証失敗（`verifyWalletUnitAttestation` / WSCD バインドで署名・vct・cnf 不一致、10102）。再取得が必要なため再試行不可。 */
  WUA_VERIFICATION_FAILED: '10102',
  /** WUA 期限切れ（`verifyWalletUnitAttestation` で TTL 超過、10103）。`refreshWalletAttestation` で解消。 */
  WUA_LIFETIME_EXPIRED: '10103',
  /** Passkey Assertion 不正（`buildWuaProofOfPossession` で signer 鍵が WUA cnf に不一致、10104）。再認証が必要なため再試行不可。 */
  PASSKEY_ASSERTION_INVALID: '10104',
  /** Transaction Data ハッシュ不一致（`addKeyBindingWithTransactionData` で同意済みハッシュと KB-JWT の `transaction_data_hashes` が不一致、`verifyTransactionDataHashes` で受領 KB-JWT のハッシュが要求と不一致、10402）。同意改ざんの疑いのため再試行不可。 */
  TRANSACTION_DATA_HASH_MISMATCH: '10402',
  /** Pseudonym Attestation バインド不一致（`issuePseudonymAttestation` で HKDF 派生鍵と署名鍵が不一致、10010）。再派生が必要なため再試行不可。 */
  PSEUDONYM_BINDING_INVALID: '10010',
  /** RP 識別子不正（`derivePseudonym` / `issuePseudonymAttestation` で形式違反・未登録 RP、10201）。RP 識別子確認が必要なため再試行不可。 */
  RP_IDENTIFIER_INVALID: '10201',
  /** 鍵派生失敗（`derivePseudonym` で HKDF 入力不正・出力が P-256 有効 scalar 範囲外、10202）。入力確認の上で再派生が必要なため再試行不可。 */
  KEY_DERIVATION_FAILED: '10202',
  /** GDPR Art.9 特別カテゴリ属性のオンチェーン投下（10601）。 */
  GDPR_SPECIAL_CATEGORY_ON_CHAIN: '10601',
  /** 法的義務による削除拒否（`deleteCredential` 対象が Art.17(3)(b) 該当、10602）。 */
  GDPR_LEGAL_OBLIGATION: '10602',
  /** 該当スコープの同意が存在しない（`revokeConsent` のスコープ未指定、GDPR Art.7(3)、10603）。撤回で Pseudonym 破棄済みの RP への提示前確認（`assertPseudonymNotDiscarded`、`reason: 'pseudonym_discarded'`）にも用いる。 */
  GDPR_CONSENT_NOT_FOUND: '10603',
  /** インポート先の Dashboard ログが空でない（`importDashboardLog` の chain 競合、Art.20、10604）。 */
  GDPR_DASHBOARD_LOG_NOT_EMPTY: '10604',
  /**
   * DSR / DPO の `.well-known` 発見メタデータの取得に失敗（ネットワークエラー / タイムアウト / HTTP
   * 4xx・5xx / 非 HTTPS リダイレクト、GDPR Art.15–22 / Art.37–39、10605）。ネットワーク要因が主因のため再試行可能。
   */
  GDPR_DISCOVERY_FETCH_FAILED: '10605',
  /**
   * DSR / DPO の `.well-known` 発見メタデータが不正（Content-Type 不一致 / JSON parse 失敗 /
   * スキーマ不正、GDPR Art.15–22 / Art.37–39、10606）。取得は成功しているが内容が不正なため再試行不可。
   */
  GDPR_DISCOVERY_INVALID: '10606',
  /** 特別カテゴリ属性を含むクレーム・発行オプションでの VC 発行（10607）。非オンチェーンのため 10601 と別コード。 */
  GDPR_SPECIAL_CATEGORY_ISSUANCE: '10607',
  /** ETSI TSL 取得失敗（HTTP エラー、5001）。ネットワーク要因のため再試行可能（Fail-safe FO-5）。 */
  TSL_FETCH_FAILED: '5001',
  /** TSL XML 署名検証失敗（改ざん / 鍵不一致、5002）。拒否。 */
  TSL_SIG_INVALID: '5002',
  /** EU LOTL 取得失敗（HTTP エラー、10301）。ネットワーク要因のため再試行可能。 */
  LOTL_FETCH_FAILED: '10301',
  /** XMLDSig 検証失敗（LOTL / TSL の署名不一致・改ざん、10302）。拒否。 */
  XMLDSIG_VERIFICATION_FAILED: '10302',
  /** Qualified Certificate 無効（期限切れ / 失効 / チェーン不成立、10303）。 */
  QUALIFIED_CERT_INVALID: '10303',
  /** ARF Trust Anchor 未登録 / カタログ署名不一致（Wallet Provider Registry 未掲載、10305）。fail-closed のため再試行不可。 */
  ARF_TRUST_ANCHOR_NOT_REGISTERED: '10305',
  /** OpenID Federation Trust Chain 不成立（Trust Anchor から到達不能・署名/policy 不整合、5010）。 */
  TRUST_CHAIN_INVALID: '5010',
  /** OpenID Federation Entity Configuration 取得失敗（HTTP エラー / パース失敗、5011）。 */
  FEDERATION_FETCH_FAILED: '5011',
  /** Subordinate Statement の鍵無効化宣言（`revoked_keys`）に該当する鍵での署名（5012）。fail-closed（FC-11）で override 不可。 */
  FEDERATION_KEY_REVOKED: '5012',
  /** RP Access Certificate 署名検証失敗 / 無効（改ざん / 発行元鍵不一致 / チェーン不成立、10306）。 */
  RP_ACCESS_CERT_SIG_INVALID: '10306',
  /** RP Access Certificate 失効済み（CRL / OCSP / Trusted List で失効、10308）。 */
  RP_ACCESS_CERT_REVOKED: '10308',
  /** RP Access Certificate 有効期間外（notBefore / notAfter 範囲外、10309）。 */
  RP_ACCESS_CERT_OUT_OF_VALIDITY: '10309',
  /** 要求属性が RP Access Certificate のスコープ外（Authorized Attributes 不一致、10310）。 */
  RP_ACCESS_SCOPE_VIOLATION: '10310',
  /** 要求目的 (purpose) が RP Access Certificate の Authorized Purposes 外（10311）。 */
  RP_ACCESS_PURPOSE_VIOLATION: '10311',
  /** RP 所在国が不明または第三国（Cross-border 転送警告、10312）。 */
  RP_CROSS_BORDER_WARNING: '10312',
  /** 選択 VC の evidence が要求 LoA を満たさない（`createPresentation` の `checkLoa` フック、10030）。再認証・別 VC 選択が必要なため再試行不可。 */
  LOA_MISMATCH: '10030',
} as const;
