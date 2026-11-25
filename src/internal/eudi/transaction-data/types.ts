/**
 * Transaction Data（OID4VP 拡張 / EUDI・HAIP）の内部型定義。
 *
 * OID4VP（draft-ietf-oauth-transaction-data / OpenID4VP §5.1）では Transaction Data は
 * Authorization Request の `transaction_data` パラメータに **base64url でエンコードされた JSON
 * オブジェクトの配列** として運ばれる。各要素は少なくとも以下を持つ:
 * - `type`: Transaction Data の種別（例: `payment` / RP 定義の識別子）。
 * - `credential_ids`: この Transaction Data を紐付ける Credential の ID 配列（DCQL の id 等）。
 * - `transaction_data_hashes_alg`（任意）: KB-JWT の `transaction_data_hashes` 計算に使う
 *   ハッシュアルゴリズム識別子の配列。省略時は `sha-256` 既定（本 SDK は `sha-256` のみ対応）。
 *
 * 種別固有の追加フィールド（金額・相手方など）は `claims` に保持し、Holder への同意提示 UI と
 * `transaction_data_hashes` 計算（生の base64url 文字列に対する SHA-256）に用いる。
 */

/** Transaction Data のハッシュアルゴリズム識別子。本 SDK は SHA-256 のみ対応。 */
export const TRANSACTION_DATA_HASH_ALG = 'sha-256';

/**
 * 抽出済み Transaction Data の 1 要素。
 *
 * `encoded` は Authorization Request 上の生の base64url 文字列で、`transaction_data_hashes`
 * 計算はこの文字列に対して行う（デコード後の再エンコードではなく受領値そのもの）。
 */
export interface TransactionDataEntry {
  /** Transaction Data の種別（`type`）。 */
  readonly type: string;
  /** 紐付け対象 Credential の ID 配列（`credential_ids`）。 */
  readonly credentialIds: readonly string[];
  /** ハッシュアルゴリズム識別子の配列（`transaction_data_hashes_alg`、省略時は `['sha-256']`）。 */
  readonly hashAlgorithms: readonly string[];
  /** 種別固有フィールドを含むデコード済み JSON オブジェクト全体（同意提示 UI 用）。 */
  readonly claims: Readonly<Record<string, unknown>>;
  /** Authorization Request 上の生 base64url 文字列（ハッシュ計算の入力）。 */
  readonly encoded: string;
}

/** Dashboard ログに記録する Transaction Data 同意イベントの payload。 */
export interface TransactionDataConsentPayload {
  /** 提示先 Verifier 識別子（`client_id` / audience）。 */
  readonly clientId: string;
  /** リプレイ防止ナンス（Authorization Request の `nonce`）。 */
  readonly nonce: string;
  /** 各 Transaction Data の種別（内容そのものは含めず種別のみ記録する）。 */
  readonly transactionDataTypes: readonly string[];
  /** KB-JWT に格納した `transaction_data_hashes`（base64url SHA-256）。 */
  readonly transactionDataHashes: readonly string[];
  /** ハッシュアルゴリズム識別子（`transaction_data_hashes_alg`）。 */
  readonly hashAlgorithm: string;
}
