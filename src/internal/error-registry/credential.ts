/**
 * 3xxx VC / VP のエラー定義（schemas/error-codes.json）。
 *
 * `message` には秘密情報を一切含めない。
 */

import type { ErrorRegistryPart } from './definition.js';

/** 3xxx（vc）のコード → 定義。 */
export const CREDENTIAL_ERRORS: ErrorRegistryPart = {
  // SD-JWT VC Type Metadata / スキーマ文書の取得失敗。ネットワーク要因が主因のため再試行可能。
  // FO-3 の既定は警告通過（呼び出し側が fail-closed に格上げ可能）。
  '3060': { category: 'vc', retriable: true, message: 'Type Metadata の取得に失敗しました' },
  // Type Metadata の構造不正（vct 不一致・schema/schema_uri 併記・extends 循環）。
  // Issuer 側の是正が必要なため再試行不可。
  '3061': { category: 'vc', retriable: false, message: 'Type Metadata の構造が不正です' },
  // credentialSchema 必須属性違反 / VC 構造不正（必須クレーム欠落・型不正等）。Issuer 是正が必要なため再試行不可。
  '3002': {
    category: 'vc',
    retriable: false,
    message: 'VC の credentialSchema 必須属性に違反しています',
  },
  // credentialSchema のスキーマ文書取得失敗（非 HTTPS / HTTP エラー / タイムアウト / 非 JSON /
  // 1 MiB 超過）。ネットワーク要因が主因のため再試行可能。
  '3015': { category: 'vc', retriable: true, message: 'スキーマ文書の取得に失敗しました' },
  // credentialSchema フィールドも schema 引数も未指定。入力の是正が必要なため再試行不可。
  '3016': {
    category: 'vc',
    retriable: false,
    message: '検証に使用する JSON Schema が指定されていません',
  },
  // Holder DID フォーマット不正（`did:<method>:<identifier>` に合致しない）。入力の是正が必要なため再試行不可。
  '3006': { category: 'vc', retriable: false, message: 'Holder DID の形式が不正です' },
  // Status List のインデックス枯渇（容量超過）。新しい Status List の生成が必要なため再試行不可。
  '3007': {
    category: 'vc',
    retriable: false,
    message: 'Status List のインデックスが枯渇しました',
  },
  // Offer URI 形式不正（不正な URI / JSON）。Offer を取り直す必要があるため再試行不可。
  '3003': {
    category: 'vc',
    retriable: false,
    message: 'Credential Offer URI のパースに失敗しました',
  },
  // 発行者との通信失敗（HTTP エラー / ネットワーク不通）。再試行で解決し得る。
  '3004': { category: 'vc', retriable: true, message: '発行者との通信に失敗しました' },
  // VC / VP 署名検証失敗（鍵不一致 / 改ざん）。fail-closed のため再試行不可。
  '3010': { category: 'vc', retriable: false, message: 'VC / VP の署名検証に失敗しました' },
  // ヘッダ alg=none は自明な攻撃のため拒否（再試行不可）。
  '3011': {
    category: 'vc',
    retriable: false,
    message: 'VC / VP のヘッダ alg=none は許可されません',
  },
  // Holder Binding 不一致（iss≠holder / aud・nonce 不一致など提示バインド失敗）。正しい鍵・文脈で再提示が必要なため再試行不可。
  '3012': {
    category: 'vc',
    retriable: false,
    message: 'Holder Binding が一致しません',
  },
  // VC が Token Status List 未対応（status クレーム未設定）。対応 VC の利用が必要なため再試行不可。
  '3018': {
    category: 'vc',
    retriable: false,
    message: 'VC は Token Status List に対応していません',
  },
  // 署名アルゴリズムが暗号アジリティレジストリで prohibited 段階。
  // fail-closed のため再試行不可。Issuer に現行アルゴリズムでの再発行を要求する必要がある。
  '3019': {
    category: 'vc',
    retriable: false,
    message: '署名アルゴリズムは禁止（prohibited）段階のため検証を拒否しました',
  },
  // VC が失効済み。Issuer から再発行が必要なため再試行不可。
  '3020': { category: 'vc', retriable: false, message: 'VC は失効しています' },
  // VC が一時停止中（Status List の suspension bit）。Issuer へ解除依頼が必要なため再試行不可。
  '3021': { category: 'vc', retriable: false, message: 'VC は一時停止されています' },
  // 新 VC の検証失敗（署名 / スキーマ / 失効）。Issuer 是正が必要なため再試行不可。
  '3022': { category: 'vc', retriable: false, message: 'リフレッシュ VC の検証に失敗しました' },
  // Holder 同意が取得できない（同意 UI で拒否等）。再同意が必要なため再試行不可。
  '3023': { category: 'vc', retriable: false, message: 'リフレッシュの同意が得られませんでした' },
  // refreshService 呼び出し失敗（HTTP エラー等）。ネットワーク要因が主因のため再試行可能（FO-9）。
  '3030': { category: 'vc', retriable: true, message: 'VC のリフレッシュに失敗しました' },
  // Manifest 不正（3031）/ 未対応 spec_version（3032）は Issuer 是正が必要で再試行不可。取得失敗（3034）は再試行可能。
  '3031': { category: 'vc', retriable: false, message: 'Credential Manifest が不正です' },
  '3032': {
    category: 'vc',
    retriable: false,
    message: 'Credential Manifest の spec_version が未対応です',
  },
  '3034': { category: 'vc', retriable: true, message: 'Credential Manifest の取得に失敗しました' },
  // refreshService 未設定。Issuer に refresh 対応 VC の再発行依頼が必要なため再試行不可。
  '3033': { category: 'vc', retriable: false, message: 'refreshService が設定されていません' },
  // Notification 用アクセストークンが不正（期限切れ / 不一致）。再認証が必要なため再試行不可。
  '3041': {
    category: 'vc',
    retriable: false,
    message: 'Notification のアクセストークンが不正です',
  },
  // 未知の notification_id（サーバー側レコードなし / 期限切れ）。正しい id の再送が必要なため再試行不可。
  '3042': { category: 'vc', retriable: false, message: '未知の notification_id です' },
  // Verifier 要求 VP format を 1 つも満たせない（format / alg 不一致）。互換 format の再発行が必要なため再試行不可。
  '3050': {
    category: 'vc',
    retriable: false,
    message: 'Verifier 要求の VP フォーマットに対応できません',
  },
  // VC の有効期限切れ（exp 超過）。Issuer から再発行が必要なため再試行不可。
  '3024': { category: 'vc', retriable: false, message: 'VC の有効期限が切れています' },
  // VC 有効化前（nbf 前）。有効化時刻まで待機が必要なため再試行不可。
  '3025': { category: 'vc', retriable: false, message: 'VC はまだ有効化されていません' },
  // 選択 VC が PEx / DCQL の要件に合致しない。要件を満たす別 VC の選択が必要なため再試行不可。
  '3080': { category: 'vc', retriable: false, message: '選択された VC が要件に合致しません' },
  // Holder 証明（proof）の検証失敗（署名不一致 / nonce 不一致 / 期限切れ）。再生成が必要なため再試行不可。
  '3081': { category: 'vc', retriable: false, message: 'Holder 証明の検証に失敗しました' },
  // 指定された VC が見つからない（削除済み / 未受領 / vcId 不正）。正しい vcId の指定が必要なため再試行不可。
  '3070': { category: 'vc', retriable: false, message: '指定された VC が見つからない' },
};
