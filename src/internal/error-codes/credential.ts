/**
 * 3xxx VC / VP のエラーコード定数（schemas/error-codes.json）。
 *
 * `errors.ts` の `ErrorCodes` に結合される部分定数。値は数値文字列。
 */

/** 3xxx（vc）のコード（数値文字列）。 */
export const CREDENTIAL_ERROR_CODES = {
  /** credentialSchema 必須属性違反 / VC 構造不正（3002）。 */
  VC_SCHEMA_INVALID: '3002',
  /** Holder DID フォーマット不正（3006）。 */
  HOLDER_DID_FORMAT_INVALID: '3006',
  /** Status List のインデックス枯渇（リスト容量超過）（3007）。 */
  STATUS_LIST_INDEX_EXHAUSTED: '3007',
  /** Credential Offer URI のパースに失敗（不正な URI 形式、3003）。 */
  OFFER_URI_PARSE_FAILED: '3003',
  /** 発行者との通信失敗（HTTP エラー / ネットワーク不通、3004）。 */
  ISSUER_COMMUNICATION_FAILED: '3004',
  /** VC / VP 署名検証失敗（鍵不一致 / 改ざん、3010）。 */
  SIG_INVALID: '3010',
  /** VC / VP ヘッダ `alg=none`（3011）。 */
  ALG_NONE: '3011',
  /** Holder Binding 不一致（cnf と提示鍵が別 / iss≠holder / aud・nonce 不一致、3012）。 */
  HOLDER_BIND_MISMATCH: '3012',
  /** credentialSchema のスキーマ文書取得失敗（非 HTTPS / HTTP エラー / 非 JSON / サイズ超過、3015）。 */
  SCHEMA_FETCH_FAILED: '3015',
  /** credentialSchema も schema 引数も未指定でスキーマ URL を解決できない（3016）。 */
  SCHEMA_NOT_SPECIFIED: '3016',
  /** VC が Token Status List 未対応（status クレーム未設定）（3018）。 */
  TOKEN_STATUS_LIST_UNSUPPORTED: '3018',
  /** 署名アルゴリズムが暗号アジリティレジストリで `prohibited` 段階のため検証拒否（3019）。 */
  VERIFY_ALGO_PROHIBITED: '3019',
  /** VC 失効（3020）。 */
  VC_REVOKED: '3020',
  /** VC 一時停止（Status List の suspension bit）（3021）。 */
  VC_SUSPENDED: '3021',
  /** リフレッシュで受領した新 VC の検証失敗（署名 / スキーマ / 失効、3022）。 */
  REFRESHED_VC_VERIFICATION_FAILED: '3022',
  /** リフレッシュに必要な Holder 同意が取得できない（3023）。 */
  HOLDER_CONSENT_NOT_OBTAINED: '3023',
  /** refreshService 呼び出し失敗（HTTP エラー等、3030）。 */
  REFRESH_FAILED: '3030',
  /** Credential Manifest スキーマ違反（3031）/ 未対応 spec_version（3032）/ 取得失敗（3034）。 */
  MANIFEST_SCHEMA_INVALID: '3031',
  MANIFEST_SPEC_VERSION_UNSUPPORTED: '3032',
  MANIFEST_FETCH_FAILED: '3034',
  /** VC に `refreshService` プロパティが未設定（3033）。 */
  REFRESH_SERVICE_NOT_SET: '3033',
  /** Notification 用アクセストークン不正（期限切れ / 不一致、3041）。 */
  NOTIFICATION_ACCESS_TOKEN_INVALID: '3041',
  /** 未知の notification_id（サーバー側レコードなし / 期限切れ、3042）。 */
  NOTIFICATION_ID_UNKNOWN: '3042',
  /** VC 有効期限切れ＝exp 超過（3024）。 */
  VC_EXPIRED: '3024',
  /** VC 有効化前＝nbf 前（3025）。 */
  VC_NOT_YET_VALID: '3025',
  /** 選択 VC が要件（PEx / DCQL）に合致しない（3080）。 */
  VC_REQUIREMENT_MISMATCH: '3080',
  /** Holder 証明（proof）の検証失敗（3081）。 */
  HOLDER_PROOF_INVALID: '3081',
  /** Verifier 要求 VP format を 1 つも満たせない（format negotiation 不成立、3050）。 */
  VP_FORMATS_NOT_SUPPORTED: '3050',
  /** SD-JWT VC Type Metadata / スキーマ文書の取得失敗（非 HTTPS / HTTP エラー / 非 JSON、3060）。 */
  TYPE_METADATA_FETCH_FAILED: '3060',
  /** SD-JWT VC Type Metadata の構造不正（vct 不一致 / schema 併記 / extends 循環、3061）。 */
  TYPE_METADATA_INVALID: '3061',
  /** 指定された VC が見つからない（削除済み / 未受領 / vcId 不正、3070）。 */
  VC_NOT_FOUND: '3070',
} as const;
