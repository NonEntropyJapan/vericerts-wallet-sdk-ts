/**
 * 4xxx Chain/W2W / 7xxx Account Abstraction / 8xxx Protocol のエラー定義
 * （schemas/error-codes.json）。
 *
 * `message` には秘密情報を一切含めない。
 */

import type { ErrorRegistryPart } from './definition.js';

/** 4xxx（nonce: Chain / W2W / SIOPv2）/ 7xxx（aa）/ 8xxx（protocol）のコード → 定義。 */
export const ACCOUNT_PROTOCOL_ERRORS: ErrorRegistryPart = {
  // DIDベース SIOPv2。不正な URI / 必須パラメータ欠落・JAR 形式は再送しても解決
  // しないため再試行不可。RP 登録情報（`registration` パラメータ）の不整合も RP 側の設定修正が
  // 必要なため同様に再試行不可。
  '4001': { category: 'nonce', retriable: false, message: 'SIOPv2 リクエストのパース失敗' },
  '4002': { category: 'nonce', retriable: false, message: 'RP 登録情報の検証失敗' },
  // nonce / replay 検知。いずれも同一入力の再送では解決しないため再試行不可。
  // 4011 / 4014 は「新しい nonce の取得」「端末時刻の同期」という別入力での再実行が必要で、
  // retriable=true（同一リクエストの再送で解決し得る）には当たらない。
  '4010': { category: 'nonce', retriable: false, message: 'nonce の再利用を検知しました' },
  '4011': { category: 'nonce', retriable: false, message: 'nonce の有効期限が切れています' },
  '4012': {
    category: 'nonce',
    retriable: false,
    message: 'nonce のバインディングが一致しません',
  },
  '4013': {
    category: 'nonce',
    retriable: false,
    message: 'nonce のフォーマットが不正またはエントロピーが不足しています',
  },
  // replay-window 外の nonce 時刻、および VC / VP / KB-JWT の時刻クレーム検証で
  // クロックスキュー許容を超えて未来の iat を検出した場合。
  // message に iat / now 等の値は含めない。
  '4014': {
    category: 'nonce',
    retriable: false,
    message: '許容時刻ウィンドウ（クロックスキュー）を超過しています',
  },
  // clockSkewSeconds オプションが不正（非負整数でない / 種別上限超過）。呼び出し側入力の問題のため再試行不可。
  '4015': {
    category: 'nonce',
    retriable: false,
    message: 'clockSkewSeconds オプションの指定が不正です',
  },
  // Credential Chain の構造エラー（循環 / 深度超過 / 親解決不能）。構造の是正が必要なため再試行不可。
  '4050': { category: 'nonce', retriable: false, message: 'Chain の循環参照を検出しました' },
  '4051': { category: 'nonce', retriable: false, message: 'Chain が最大深度を超えています' },
  '4052': { category: 'nonce', retriable: false, message: 'Chain の親 VC を解決できません' },
  // EVM アドレス形式不正（0x + 40 hex 以外）。呼び出し側入力の問題のため再試行不可。
  '4070': { category: 'nonce', retriable: false, message: 'EVM アドレス形式が不正です' },
  // 対象チェーンが未設定（RPC 未設定の chainId）。設定の問題のため再試行不可。
  '4071': { category: 'nonce', retriable: false, message: '対象チェーンが設定されていません' },
  // W2W: 新端末 Wallet Integrity（attestation）検証失敗。端末側の問題のため再試行不可。
  '4031': {
    category: 'nonce',
    retriable: false,
    message: '新端末の Wallet Integrity 検証に失敗しました',
  },
  // W2W: Backup 復号のパスフレーズ誤り。入力誤りのため再試行不可（正しいパスフレーズなら別途成功）。
  '4032': {
    category: 'nonce',
    retriable: false,
    message: 'バックアップのパスフレーズが誤っています',
  },
  // W2W: Backup の完全性証明（署名）検証失敗＝改ざん。再試行不可。
  '4033': { category: 'nonce', retriable: false, message: 'バックアップの署名検証に失敗しました' },
  // W2W: Lend トークンの有効期限切れ。期限超過のため再試行不可（再発行が必要）。
  '4034': { category: 'nonce', retriable: false, message: 'Lend トークンの有効期限が切れています' },
  // W2W: 旧端末 VC の無効化（失効通知送信）失敗。ネットワーク要因が主因のため再試行可能。
  '4035': { category: 'nonce', retriable: true, message: '旧端末の VC 無効化に失敗しました' },
  // W2W: バックアップのバージョン非対応。対応バージョンの Wallet が必要なため再試行不可。
  '4036': {
    category: 'nonce',
    retriable: false,
    message: 'バックアップのバージョンに対応していません',
  },
  // DPoP（RFC 9449）: proof JWT の形式不正（typ/alg 不正・jwk 欠落・必須クレーム欠落・パース失敗）。
  // proof の再生成が必要なため再試行不可。message に proof / トークン / 鍵素材は含めない。
  '4080': { category: 'nonce', retriable: false, message: 'DPoP proof の形式が不正です' },
  // DPoP: header jwk に対する署名検証失敗（改ざん）。proof の再生成が必要なため再試行不可。
  '4081': { category: 'nonce', retriable: false, message: 'DPoP proof の署名検証に失敗しました' },
  // DPoP: iat が許容ウィンドウ外（max age 超過 / クロックスキュー）。時刻同期後の再生成が必要。
  '4082': {
    category: 'nonce',
    retriable: false,
    message: 'DPoP proof の発行時刻が許容範囲外です',
  },
  // DPoP: htm / htu がリクエストと不一致（別エンドポイント向け proof の流用）。再試行不可。
  '4083': {
    category: 'nonce',
    retriable: false,
    message: 'DPoP proof がリクエストと一致しません',
  },
  // DPoP: ath がアクセストークンのハッシュと不一致（組み合わせ誤り）。再試行不可。
  '4084': {
    category: 'nonce',
    retriable: false,
    message: 'DPoP proof がアクセストークンと一致しません',
  },
  // DPoP: cnf.jkt と proof 公開鍵のサムプリントが不一致（束縛鍵と異なる鍵での提示）。再試行不可。
  '4085': {
    category: 'nonce',
    retriable: false,
    message: 'DPoP proof の鍵が束縛された鍵と一致しません',
  },
  // DPoP: nonce の欠落・陳腐化。新しい DPoP-Nonce を受け取って proof を作り直せば成功し得るため
  // 再試行可能（RFC 9449 §8 / §9 の use_dpop_nonce チャレンジ）。
  '4086': {
    category: 'nonce',
    retriable: true,
    message: '新しい DPoP-Nonce での proof 再生成が必要です',
  },
  // 7xxx Account Abstraction。Bundler / Paymaster 拒否・UserOp 再構築・ZK 再生成等は再試行可能。
  // Bundler 側シミュレーション失敗（残高不足 / ガス）。UserOp を再構築すれば解消し得るため再試行可能。
  '7001': {
    category: 'aa',
    retriable: true,
    message: 'UserOperation のシミュレーションに失敗しました',
  },
  // Bundler がステートレス検証等で拒否。別 Bundler で解消し得るため再試行可能。
  '7002': { category: 'aa', retriable: true, message: 'Bundler が UserOperation を拒否しました' },
  // Paymaster が Sponsorship ポリシー違反等で拒否。ポリシー確認後に解消し得るため再試行可能。
  '7003': { category: 'aa', retriable: true, message: 'Paymaster が UserOperation を拒否しました' },
  // SmartAccount に該当 Validator が未登録。登録が必要なため再試行不可。
  '7010': { category: 'aa', retriable: false, message: 'Validator が登録されていません' },
  // SSO ZK Proof 不正（id_token 期限切れ等）。再ログインが必要なため再試行不可。
  '7020': { category: 'aa', retriable: false, message: 'SSO ZK Proof が不正です' },
  // 署名者の追加 / 削除権限なし。管理権限のあるペルソナが必要なため再試行不可。
  '7101': { category: 'aa', retriable: false, message: '署名者の管理権限がありません' },
  // 署名者が既に登録済み（重複登録）。再試行不可。
  '7102': { category: 'aa', retriable: false, message: '署名者は既に登録されています' },
  // 最後の署名者は削除不可（アカウントロックアウト防止）。別署名者の追加が必要なため再試行不可。
  '7103': { category: 'aa', retriable: false, message: '最後の署名者は削除できません' },
  // ファクトリー呼び出し失敗（RPC エラー / バイトコード不正 / コンストラクタ revert）。ネットワーク要因が主因のため再試行可能。
  '7050': {
    category: 'aa',
    retriable: true,
    message: 'ファクトリーコントラクトの呼び出しに失敗しました',
  },
  // スマートアカウントが既にデプロイ済み（二重デプロイ要求）。再試行不可。
  '7051': { category: 'aa', retriable: false, message: 'スマートアカウントは既にデプロイ済みです' },
  // WebAuthn assertion の入力形式不正（DER デコード失敗 / clientDataJSON の challenge・type 欠落 / r,s 長超過）。assertion の取得やり直しが必要なため再試行不可。署名の真正性はオンチェーンで検証される。
  '7150': { category: 'aa', retriable: false, message: 'P-256 署名の検証に失敗しました' },
  // ZK 証明生成失敗（回路実行エラー / 入力不正）。入力確認後に解消し得るため再試行可能。
  '7201': { category: 'aa', retriable: true, message: 'ZK 証明の生成に失敗しました' },
  // id_token 有効期限切れ（TTL 超過）。再ログインが必要なため再試行不可。
  '7202': { category: 'aa', retriable: false, message: 'id_token の有効期限が切れています' },
  // issuer が未対応（Google/Apple 以外）。対応 IdP が必要なため再試行不可。
  '7203': { category: 'aa', retriable: false, message: '未対応の SSO issuer です' },
  // Issuer Metadata 取得失敗（HTTP エラー）。再試行で解決し得る。
  '8001': {
    category: 'protocol',
    retriable: true,
    message: 'Issuer Metadata の取得に失敗しました',
  },
  // Token Request 失敗（pre-authorized_code 不正 / HTTP エラー等）。code 再取得が必要なため再試行不可。
  '8010': { category: 'protocol', retriable: false, message: 'Token Request に失敗しました' },
  // Credential Request 失敗（c_nonce 期限切れ / proof 不正 / HTTP エラー等）。再試行不可。
  '8020': { category: 'protocol', retriable: false, message: 'Credential Request に失敗しました' },
  // Credential の型を Issuer Metadata から決められない（`vct` も `credential_definition.type` も告知が無い等）。Issuer 側の告知が直るまで再試行しても解決しないため再試行不可。
  '8021': {
    category: 'protocol',
    retriable: false,
    message: 'Credential の型を Issuer Metadata から決められません',
  },
  // Presentation Request パース失敗（JAR 署名検証失敗 / DCQL 構文エラー等）。Verifier 確認が必要なため再試行不可。
  '8030': {
    category: 'protocol',
    retriable: false,
    message: 'Presentation Request のパースに失敗しました',
  },
  // OID4VP 経路の PAR push 失敗（HTTP エラー / ネットワーク不通 / 応答不正 / 非 HTTPS / 必須欠落）。
  // エラーコード 8010 とは異なりドメインを混ぜないため専用コードとする。
  // エラーコード 8035 と同じく HTTP / ネットワーク要因は再送で解決し得るため再試行可能とする。
  '8031': {
    category: 'protocol',
    retriable: true,
    message: 'OID4VP 経路の PAR push に失敗しました',
  },
  // direct_post 送信失敗（HTTP エラー / ネットワーク不通）または未対応 response_mode。
  // HTTP / ネットワーク要因は再送で解決し得るため再試行可能とする（VP Token は再構築不要）。
  '8035': {
    category: 'protocol',
    retriable: true,
    message: 'VP Token の送信に失敗しました',
  },
  // `direct_post.jwt` の応答暗号化パラメータを解決できない（client_metadata 欠落・未対応 JWE alg/enc・
  // use:"enc" 鍵が無い）。Verifier 側メタデータの是正が必要なため再試行不可。
  '8036': {
    category: 'protocol',
    retriable: false,
    message: 'VP 応答の暗号化パラメータを解決できません',
  },
  // `direct_post.jwt` の JWE 構築失敗（ECDH-ES 鍵導出・AES-GCM / AES-KW 演算の失敗）。実行環境の
  // Web Crypto 能力に依存する恒久的失敗のため再試行不可。鍵・平文は message に含めない。
  '8037': {
    category: 'protocol',
    retriable: false,
    message: 'VP 応答の暗号化に失敗しました',
  },
  // SIWE（EIP-4361）メッセージのパース / 検証失敗（必須欠落・version 不正・nonce 形式・期限切れ・domain 不一致）。
  // 入力（メッセージ本文 / nonce / 有効期限）の是正が必要なため再試行不可。message に本文・アドレス等は含めない。
  '8041': {
    category: 'protocol',
    retriable: false,
    message: 'SIWE メッセージのパース / 検証に失敗しました',
  },
  // 要求フォーマットが SDK 未対応（DCQL の format が非対応）。対応形式の VC が必要なため再試行不可。
  '8050': {
    category: 'protocol',
    retriable: false,
    message: '要求されたフォーマットは未対応です',
  },
};
