/**
 * 4xxx Chain/W2W / 7xxx Account Abstraction / 8xxx Protocol のエラーコード定数
 * （schemas/error-codes.json）。
 *
 * `errors.ts` の `ErrorCodes` に結合される部分定数。値は数値文字列。
 */

/** 4xxx（nonce: Chain / W2W / SIOPv2）/ 7xxx（aa）/ 8xxx（protocol）のコード（数値文字列）。 */
export const ACCOUNT_PROTOCOL_ERROR_CODES = {
  /** DIDベース SIOPv2 Authorization Request のパース失敗（4001）/ RP 登録情報の検証失敗（4002）。 */
  SIOPV2_REQUEST_PARSE_FAILED: '4001',
  RP_REGISTRATION_INVALID: '4002',
  /** nonce リプレイ検知（4010）/ TTL 超過（4011）/ aud・client_id バインド不一致（4012）/ 形式不正・エントロピー不足（4013）。 */
  REPLAY_DETECTED: '4010',
  NONCE_EXPIRED: '4011',
  NONCE_BINDING_MISMATCH: '4012',
  NONCE_MALFORMED: '4013',
  /** 時刻クレームが許容ウィンドウ外（4014）: replay-window 外、または `iat` が許容値超で未来。 */
  CLOCK_SKEW_EXCEEDED: '4014',
  /** `clockSkewSeconds` オプションが不正（非負整数でない / 種別上限を超える、4015）。 */
  CLOCK_SKEW_OPTION_INVALID: '4015',
  /** Credential Chain 循環参照検出（4050）/ maxDepth 超過（4051）/ 親 VC 解決不能（4052）。 */
  CHAIN_CYCLE: '4050',
  CHAIN_TOO_DEEP: '4051',
  CHAIN_PARENT_UNRESOLVABLE: '4052',
  /** EVM アドレス形式不正（`0x` + 40 hex 以外、4070）。 */
  INVALID_EVM_ADDRESS: '4070',
  /** 対象チェーンが未設定（RPC 未設定の chainId、4071）。 */
  CHAIN_NOT_CONFIGURED: '4071',
  /** W2W: 新端末 Wallet Integrity（attestation）検証失敗（4031）。 */
  W2W_ATTESTATION_FAILED: '4031',
  /** W2W: バックアップ復号のパスフレーズ誤り（4032）。 */
  W2W_PASSPHRASE_WRONG: '4032',
  /** W2W: バックアップの完全性証明（署名）検証失敗＝改ざん（4033）。 */
  W2W_INTEGRITY_BROKEN: '4033',
  /** W2W: Lend トークンの有効期限切れ（4034）。 */
  W2W_LEND_EXPIRED: '4034',
  /** W2W: 旧端末 VC の無効化（失効通知）失敗（4035）。 */
  W2W_DOUBLE_ACTIVE: '4035',
  /** W2W: バックアップのバージョン非対応（4036）。 */
  W2W_INCOMPATIBLE_VERSION: '4036',
  /** DPoP proof 検証失敗（RFC 9449）: 形式 4080 / 署名 4081 / iat 4082 / htm・htu 4083 / ath 4084 / jkt 4085。 */
  DPOP_PROOF_MALFORMED: '4080',
  DPOP_SIGNATURE_INVALID: '4081',
  DPOP_PROOF_EXPIRED: '4082',
  DPOP_HTTP_BINDING_MISMATCH: '4083',
  DPOP_ATH_MISMATCH: '4084',
  DPOP_KEY_BINDING_MISMATCH: '4085',
  /** DPoP: `nonce` の欠落・陳腐化。`use_dpop_nonce` チャレンジで応答する（RFC 9449 §8 / §9、4086）。 */
  DPOP_NONCE_REQUIRED: '4086',
  /** Issuer Metadata 取得失敗（HTTP エラー、8001）。 */
  ISSUER_META_FETCH_FAILED: '8001',
  /** Token Request 失敗（Pre-Auth code 不正等、8010）。 */
  TOKEN_REQUEST_FAILED: '8010',
  /** Credential Request 失敗（c_nonce 期限切れ / proof 不正等、8020）。 */
  CREDENTIAL_REQUEST_FAILED: '8020',
  /** 受領する Credential の型（SD-JWT VC の `vct` / `credential_definition.type`）を Issuer Metadata から決められない（8021。拡張の受領経路が送出する）。 */
  CREDENTIAL_TYPE_UNRESOLVED: '8021',
  /** Presentation Request（OID4VP）パース失敗（JAR 署名 / DCQL 構文エラー、8030）。 */
  OID4VP_REQUEST_PARSE_FAILED: '8030',
  /** OID4VP 経路の PAR push 失敗（非 2xx・応答不正・非 HTTPS・必須欠落・ネットワーク失敗、8031）。 */
  OID4VP_PAR_REQUEST_FAILED: '8031',
  /** VP Token の direct_post 送信失敗 / 未対応 response_mode（8035）。 */
  PRESENTATION_SUBMIT_FAILED: '8035',
  /** `direct_post.jwt` 応答暗号化: パラメータ解決不能（client_metadata / alg / enc 鍵）8036、JWE 構築失敗 8037。 */
  VP_RESPONSE_ENCRYPTION_UNSUPPORTED: '8036',
  VP_RESPONSE_ENCRYPTION_FAILED: '8037',
  /** SIWE（EIP-4361）メッセージのパース / 検証失敗（必須欠落 / version≠"1" / nonce 形式 / 期限 / domain 不一致、8041）。 */
  SIWE_MESSAGE_INVALID: '8041',
  /** 要求フォーマットが未対応（DCQL の format が SDK 非対応、8050）。 */
  FORMAT_NEGOTIATION_FAILED: '8050',
  /** Bundler 側 UserOp シミュレーション失敗（残高不足 / ガス、7001）。UserOp を再構築して再試行。 */
  USEROP_SIMULATION_FAILED: '7001',
  /** Bundler がステートレス検証等で UserOp を拒否（7002）。別 Bundler で再試行可能。 */
  BUNDLER_REJECTED: '7002',
  /** Paymaster が Sponsorship ポリシー違反等で拒否（7003）。ポリシー確認後に再試行可能。 */
  PAYMASTER_REJECTED: '7003',
  /** SmartAccount に該当 Validator が未登録（7010）。 */
  VALIDATOR_NOT_FOUND: '7010',
  /** SSO ZK Proof 不正（id_token 期限切れ等、7020）。再ログインで解消。 */
  ZK_PROOF_INVALID: '7020',
  /** 署名者の追加 / 削除権限なし（アクティブペルソナに管理権限なし、7101）。 */
  SIGNER_PERMISSION_DENIED: '7101',
  /** 署名者が既に登録済み（重複登録、7102）。 */
  SIGNER_ALREADY_EXISTS: '7102',
  /** 最後の署名者は削除不可（アカウントロックアウト防止、7103）。 */
  LAST_SIGNER_REMOVAL_BLOCKED: '7103',
  /** ファクトリーコントラクト呼び出し失敗（RPC エラー / バイトコード不正 / コンストラクタ revert、7050）。 */
  FACTORY_CALL_FAILED: '7050',
  /** スマートアカウントが既にデプロイ済み（二重デプロイ要求、7051）。 */
  ACCOUNT_ALREADY_DEPLOYED: '7051',
  /** WebAuthn assertion の入力形式不正（DER デコード失敗 / clientDataJSON の challenge・type 欠落 / r,s 長超過、7150）。署名の真正性はオンチェーンで検証される。 */
  P256_SIG_INVALID: '7150',
  /** ZK 証明生成失敗（回路実行エラー / 入力不正、7201）。入力確認後に再試行可能。 */
  ZK_PROOF_GENERATION_FAILED: '7201',
  /** id_token 有効期限切れ（TTL 超過、7202）。再ログインで新しい id_token を取得。 */
  ID_TOKEN_EXPIRED: '7202',
  /** issuer が未対応（Google/Apple 以外の OIDC Provider、7203）。 */
  SSO_ISSUER_UNSUPPORTED: '7203',
} as const;
