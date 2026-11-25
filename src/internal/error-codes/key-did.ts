/**
 * 1xxx Key Management / 2xxx DID のエラーコード定数（schemas/error-codes.json）。
 *
 * `errors.ts` の `ErrorCodes` に結合される部分定数。値は数値文字列。
 */

/** 1xxx（key）/ 2xxx（did）のコード（数値文字列）。 */
export const KEY_DID_ERROR_CODES = {
  /** BIP-39 ニーモニック不正（1001）。 */
  INVALID_MNEMONIC: '1001',
  /** ワード数が 12 / 24 以外（1002）。 */
  INVALID_WORD_COUNT: '1002',
  /** 秘密鍵フォーマット不正（1003）。 */
  INVALID_PRIVATE_KEY: '1003',
  /** 指定された鍵 ID が見つからない（1004）。 */
  KEY_NOT_FOUND: '1004',
  /** 鍵がロック中＝PIN + 生体認証による未アンロック状態（1005）。 */
  KEY_LOCKED: '1005',
  /** 署名演算失敗（1020）。 */
  SIGN_FAILED: '1020',
  /** チェーン送信失敗 / RPC 呼び出し失敗（ガス不足・eth_call 失敗・戻り値不正含む、1021）。 */
  CHAIN_SUBMIT_FAILED: '1021',
  /** 未対応のアルゴリズム（1030）。 */
  UNSUPPORTED_ALGORITHM: '1030',
  /** 不正な BIP-44 導出パス（1040）。 */
  DERIVATION_PATH_INVALID: '1040',
  /** マスターシード未初期化（1041）。 */
  MASTER_SEED_NOT_INITIALIZED: '1041',
  /** ニーモニックが永続化されていない＝export 対象なし（1042）。 */
  MNEMONIC_NOT_FOUND: '1042',
  /** 既にニーモニックが永続化済みで、明示的な上書き指定なしには置き換えられない（1043）。 */
  MNEMONIC_ALREADY_PERSISTED: '1043',
  /** 復号の認証タグ検証失敗・改ざん（1050）。 */
  DECRYPT_FAILED: '1050',
  /** AES-256-GCM 暗号化失敗・鍵/IV パラメータ不正（1051）。 */
  ENCRYPT_FAILED: '1051',
  /** SLIP-0039 エンコード失敗（1011）。 */
  SHAMIR_ENCODE_FAILED: '1011',
  /** シェア数が閾値未満（1012）。 */
  SHAMIR_INSUFFICIENT_SHARES: '1012',
  /** シェア間のグループ不一致（1013）。 */
  SHAMIR_GROUP_MISMATCH: '1013',
  /** シェアのチェックサム検証失敗（1014）。 */
  SHAMIR_CHECKSUM_INVALID: '1014',
  /** threshold / total が不正（1015）。 */
  SHAMIR_INVALID_PARAMS: '1015',
  /** 有効な ECDSA Validator が存在しない（1022）。 */
  VALIDATOR_NOT_AVAILABLE: '1022',
  /** PIN ポリシー不適合（1031）。 */
  PIN_POLICY_VIOLATION: '1031',
  /** Passkey 作成失敗（1032）。 */
  PASSKEY_CREATE_FAILED: '1032',
  /** WUA 再発行失敗（1033）。 */
  WUA_REISSUE_FAILED: '1033',
  /** DID 文字列形式不正（2001）。 */
  INVALID_DID: '2001',
  /** 未対応・未登録の DID メソッド（2002）。 */
  METHOD_NOT_SUPPORTED: '2002',
  /** DID を解決できない（取得失敗・ネットワークエラー等、2003）。 */
  DID_NOT_FOUND: '2003',
  /** 指定された ID のペルソナが存在しない（2005）。 */
  PERSONA_NOT_FOUND: '2005',
  /** controller 権限なし / controller 未設定（2006）。 */
  CONTROLLER_NOT_AUTHORIZED: '2006',
  /** 指定 DID の署名鍵が利用不可（2007）。 */
  DID_SIGNING_KEY_UNAVAILABLE: '2007',
  /** 同一 index/DID のペルソナが既に存在する（2008）。 */
  PERSONA_ALREADY_EXISTS: '2008',
  /** DID ドキュメントのスキーマ不正（2010）。 */
  DID_DOC_INVALID: '2010',
  /** content-addressed DID / VC の contentHash 不一致＝すり替え検知（2009）。 */
  CONTENT_HASH_MISMATCH: '2009',
  /** contentHash 表記の形式不正・未対応表記（2016）。 */
  CONTENT_HASH_FORMAT_INVALID: '2016',
  /** 保持している公開鍵が DID Document の検証メソッド（要求した検証関係）と一致しない（2017）。 */
  DID_KEY_MISMATCH: '2017',
  /** controller 循環参照（2030）。 */
  CONTROLLER_CHAIN_LOOP: '2030',
} as const;
