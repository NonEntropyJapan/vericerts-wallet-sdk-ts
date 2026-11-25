/**
 * 5xxx Trust / 10xxx EUDI のエラー定義（schemas/error-codes.json）。
 *
 * `message` には秘密情報を一切含めない。
 */

import type { ErrorRegistryPart } from './definition.js';

/** 5xxx（trust）/ 10xxx（eudi）のコード → 定義。 */
export const TRUST_EUDI_ERRORS: ErrorRegistryPart = {
  // PID Rulebook のスキーマ検証で属性の型・形式が不正、または受領した VC の vct が
  // urn:eudi:pid:1 と不一致（Issuer 不正が主因）。是正発行が必要なため再試行不可。
  '10001': { category: 'eudi', retriable: false, message: 'PID スキーマ違反' },
  // PID Rulebook の必須属性が欠落（Issuer 不正 / 入力欠落）。是正発行が必要なため再試行不可。
  '10002': { category: 'eudi', retriable: false, message: '必須属性欠落' },
  // vct が (Q)EAA Catalogue に未掲載でスキーマ解決不能。カタログ登録が必要なため再試行不可。
  '10003': { category: 'eudi', retriable: false, message: '(Q)EAA Catalogue 未登録' },
  // Wallet Provider Backend からの WUA 取得失敗（応答エラー / ネットワーク）。要因が一時的なため再試行可能。
  '10101': { category: 'eudi', retriable: true, message: 'WUA 取得失敗' },
  // WUA の署名・vct・cnf バインド不一致。再取得が必要なため再試行不可。
  '10102': { category: 'eudi', retriable: false, message: 'WUA 検証失敗' },
  // WUA の TTL 超過。refreshWalletAttestation での再発行で解消し得るため再試行可能。
  '10103': { category: 'eudi', retriable: true, message: 'WUA 期限切れ' },
  // WUA-PoP 署名鍵が WUA cnf に不一致（Passkey Assertion 不正）。再認証が必要なため再試行不可。
  '10104': { category: 'eudi', retriable: false, message: 'Passkey Assertion 不正' },
  // addKeyBindingWithTransactionData / verifyTransactionDataHashes で同意済み・要求 Transaction Data と KB-JWT の transaction_data_hashes が不一致。同意改ざんの疑いのため再試行不可。
  '10402': { category: 'eudi', retriable: false, message: 'Transaction Data ハッシュ不一致' },
  // Pseudonym（10010 バインド不一致 / 10201 RP 識別子不正 / 10202 HKDF 鍵派生失敗）。いずれも再派生・入力確認が必要なため再試行不可。
  '10010': { category: 'eudi', retriable: false, message: 'Pseudonym Attestation バインド不一致' },
  '10201': { category: 'eudi', retriable: false, message: 'RP 識別子不正' },
  '10202': { category: 'eudi', retriable: false, message: '鍵派生失敗' },
  // GDPR Art.9 特別カテゴリ属性をオンチェーン（blockchain / IPFS / DID Document）へ投下しようとした。
  // 該当属性を除外して公開し直す必要があるため再試行不可。
  '10601': {
    category: 'eudi',
    retriable: false,
    message: '特別カテゴリ属性のオンチェーン投下',
  },
  // deleteCredential 対象が法的義務（Art.17(3)(b)）に該当し削除できない。法的義務が解けるまで再試行不可。
  '10602': { category: 'eudi', retriable: false, message: '法的義務による削除拒否' },
  // revokeConsent のスコープが未指定で撤回対象を特定できない（GDPR Art.7(3)）。スコープ指定が必要なため再試行不可。
  '10603': { category: 'eudi', retriable: false, message: '該当スコープの同意が存在しない' },
  // importDashboardLog のインポート先 Dashboard ログが空でない（既存 chain と競合、GDPR Art.20）。空の状態でのみ許可のため再試行不可。
  '10604': {
    category: 'eudi',
    retriable: false,
    message: 'インポート先の Dashboard ログが空でない',
  },
  // DSR / DPO の .well-known 発見メタデータの取得失敗（ネットワーク / タイムアウト / HTTP エラー /
  // 非 HTTPS リダイレクト、GDPR Art.15–22 / Art.37–39）。ネットワーク要因が主因のため再試行可能。
  '10605': {
    category: 'eudi',
    retriable: true,
    message: 'DSR / DPO 発見メタデータの取得に失敗しました',
  },
  // DSR / DPO の .well-known 発見メタデータが不正（Content-Type / JSON / スキーマ不正）。取得は成功
  // しているが内容が信頼できないため再試行不可。
  '10606': { category: 'eudi', retriable: false, message: 'DSR / DPO 発見メタデータが不正です' },
  // Art.9 特別カテゴリ属性を含むクレーム、または VC へ写る発行オプション（evidence / termsOfUse /
  // refreshService 等）で VC を発行しようとした（issueVC）。該当属性を除外して発行し直す
  // 必要があるため再試行不可。発行はチェーンに書き込まないため 10601 とは別コード。
  '10607': {
    category: 'eudi',
    retriable: false,
    message: '特別カテゴリ属性の VC 発行',
  },
  // 5xxx Trust。ETSI Trusted List / QCert 検証。
  // ETSI TSL 取得失敗（HTTP エラー）。ネットワーク要因が主因のため再試行可能（Fail-safe FO-5）。
  '5001': { category: 'trust', retriable: true, message: 'ETSI TSL の取得に失敗しました' },
  // TSL XML 署名検証失敗（改ざん / 鍵不一致）。信頼できないため再試行不可。
  '5002': { category: 'trust', retriable: false, message: 'TSL XML の署名検証に失敗しました' },
  // 10xxx EUDI。LOTL 取得・XMLDSig・QCert。
  // EU LOTL 取得失敗（HTTP エラー）。ネットワーク要因が主因のため再試行可能。
  '10301': { category: 'eudi', retriable: true, message: 'EU LOTL の取得に失敗しました' },
  // XMLDSig 検証失敗（署名不一致 / 改ざん）。信頼できないため再試行不可。
  '10302': { category: 'eudi', retriable: false, message: 'XMLDSig の検証に失敗しました' },
  // Qualified Certificate 無効（期限切れ / 失効 / チェーン不成立）。証明書自体の問題のため再試行不可。
  '10303': { category: 'eudi', retriable: false, message: 'Qualified Certificate が無効です' },
  // ARF Trust Anchor 未登録（Wallet Provider Registry 未掲載 / カタログ署名不一致）。
  // fail-closed。レジストリへの登録・正当な署名鍵が必要なため再試行不可。
  '10305': {
    category: 'eudi',
    retriable: false,
    message: 'ARF Trust Anchor がレジストリに登録されていません',
  },
  // 5xxx Trust。OpenID Federation Trust Framework。
  // Trust Chain 不成立（Trust Anchor から到達不能 / 署名検証失敗 / metadata_policy 不整合 / 期限切れ）。
  // fail-closed（FC-5）。構成の是正が必要なため再試行不可。
  '5010': { category: 'trust', retriable: false, message: 'Trust Chain が成立しません' },
  // Entity Configuration 取得失敗（HTTP エラー / タイムアウト / パース失敗）。
  // fail-open（FO-6）で上位レイヤにフォールバックし得るため、ネットワーク要因は再試行可能。
  '5011': {
    category: 'trust',
    retriable: true,
    message: 'Entity Configuration の取得に失敗しました',
  },
  // Subordinate Statement の鍵無効化宣言（revoked_keys）に該当する鍵での署名。
  // fail-closed（FC-11）で FailSafePolicy の fail-open 対象外。鍵の再発行が必要なため再試行不可。
  '5012': {
    category: 'trust',
    retriable: false,
    message: '無効化が宣言された鍵で署名されています',
  },
  // 10306/10308–10312 RP Access Certificate（ETSI TS 119 475）。すべて再試行不可。
  '10306': { category: 'eudi', retriable: false, message: 'RP Access Certificate が無効です' },
  '10308': { category: 'eudi', retriable: false, message: 'RP Access Certificate は失効済みです' },
  '10309': {
    category: 'eudi',
    retriable: false,
    message: 'RP Access Certificate は有効期間外です',
  },
  '10310': { category: 'eudi', retriable: false, message: '要求属性が RP のスコープ外です' },
  '10311': { category: 'eudi', retriable: false, message: '要求目的が RP のスコープ外です' },
  '10312': { category: 'eudi', retriable: false, message: 'RP が第三国または所在国不明です' },
  // createPresentation の checkLoa フックで、選択 VC の evidence（interpretEvidence / verifyEvidence）
  // が要求 LoA を満たさない。再認証・別 VC の選択が必要なため再試行不可。
  '10030': { category: 'eudi', retriable: false, message: '要求 LoA に満たない' },
};
