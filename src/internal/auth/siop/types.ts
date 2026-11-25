/**
 * DIDベース SIOPv2（Self-Issued OpenID Provider v2）の型定義。
 *
 * `src/internal/eudi/pseudonym/siop.ts` の `presentPseudonym` は EUDI Pseudonym ログイン専用
 * （`sub` が `urn:pseudonym:<hash(pub)>`）で、本モジュールが対象とする汎用の DID ベース SIOPv2
 * （`sub` が Holder の DID）とは別実装である。
 */

/**
 * RP メタデータ（`client_metadata`、後方互換で `registration`）。
 *
 * DIDベース SIOPv2 では、RP が DID を subject として受理できることを
 * `subjectSyntaxTypesSupported` で宣言している必要がある。`client_metadata`（標準）と
 * `registration`（旧形式）は同じ形に展開する。
 */
export interface RPRegistration {
  /** RP が受理する subject syntax type（例: `['did', 'did:key', 'did:web']`）。 */
  readonly subjectSyntaxTypesSupported: readonly string[];
  /**
   * RP が受理する ID Token 署名アルゴリズム（`id_token_signing_alg_values_supported`。例: `['ES256', 'ES256K']`）。
   * RP が宣言していなければ `undefined`（その場合は `idTokenSignedResponseAlg` が宣言されている）。
   */
  readonly idTokenSigningAlgValuesSupported?: readonly string[];
  /**
   * RP が要求する ID Token 署名アルゴリズム（標準の `id_token_signed_response_alg`。単一の文字列。SIOPv2 §7.2）。
   * RP が宣言していなければ `undefined`。
   */
  readonly idTokenSignedResponseAlg?: string;
  /**
   * RP が受理する JWT-VP の署名アルゴリズム（`vp_formats_supported.jwt_vp.alg_values`。OID4VP §5.1）。
   * RP が宣言していなければ `undefined`（`vp_token` を返すときだけ参照する）。
   */
  readonly jwtVpAlgValuesSupported?: readonly string[];
}

/**
 * パース済み SIOPv2 Authorization Request。
 */
export interface SIOPv2Request {
  /** 要求スコープ（`openid` を含む空白区切り文字列）。 */
  readonly scope: string;
  /** `id_token` または `vp_token id_token`（空白区切り。順不同）。 */
  readonly responseType: string;
  /** RP の識別子（URL または DID）。生成する ID Token の `aud` になる。 */
  readonly clientId: string;
  /** レスポンス（ID Token / VP Token）の POST 先（HTTPS 必須）。 */
  readonly redirectUri: string;
  /** リプレイ防止 nonce。生成する ID Token の `nonce` になる。 */
  readonly nonce: string;
  /** RP が返送時に求める `state`。`vp_token` を要求する場合は必須で、そのまま RP へ返す。 */
  readonly state?: string;
  /** 応答の返し方（`direct_post` のみ対応）。`vp_token` を要求する場合に検証する。 */
  readonly responseMode?: string;
  /** ID Token の種別（空白区切り。`subject_signed_id_token` を含むこと）。`vp_token` を要求する場合に検証する。 */
  readonly idTokenType?: string;
  /**
   * VC を求める問い合わせ（`dcql_query` / `presentation_definition` / `presentation_definition_uri` / `claims`）が
   * 載っているか。Wallet は評価できない（VC を見せるログインは対象外）ので、`vp_token` を要求する場合は拒否する。
   */
  readonly requestsCredentials?: boolean;
  /** RP メタデータ（`client_metadata`。標準の置き場所。`registration` より優先する）。 */
  readonly clientMetadata?: RPRegistration;
  /** RP メタデータ（`registration`。旧形式。`client_metadata` が無いときだけ使う）。 */
  readonly registration?: RPRegistration;
  /**
   * RP メタデータの取得先（`client_metadata_uri`。公開 HTTPS URL。`client_metadata` と同時には使えない）。
   * `processSIOPv2Request` が承認後に取得して `clientMetadata` と同じ検査を行う。パース時点では取得しない。
   */
  readonly clientMetadataUri?: string;
}

/**
 * `processSIOPv2Request` の結果。
 *
 * `redirectUri` は要求の `redirect_uri` をそのまま返す。ID Token（と VP Token）の POST 送信自体は上位層
 * （wallet / extension）の責務だが、送信先を呼び出し側が要求から読み直さずに済むよう含める。
 */
export interface SIOPv2Response {
  /** 署名済み自己発行 ID Token（`sub` = Holder の DID）。 */
  readonly idToken: string;
  /** レスポンスの POST 先（要求の `redirect_uri`）。 */
  readonly redirectUri: string;
  /**
   * 署名済み VP Token（`typ=vp+jwt`。VC を含まない）。要求の `response_type` が `vp_token` を含むときだけ付く。
   * `holder` は ID Token の `iss` と同じ DID。
   */
  readonly vpToken?: string;
  /** 要求の `state`（`vp_token` を要求したときだけ付く。RP へそのまま返す）。 */
  readonly state?: string;
}
