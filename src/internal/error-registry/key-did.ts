/**
 * 1xxx Key Management / 2xxx DID のエラー定義（schemas/error-codes.json）。
 *
 * `message` には秘密情報を一切含めない。
 */

import type { ErrorRegistryPart } from './definition.js';

/** 1xxx（key）/ 2xxx（did）のコード → 定義。 */
export const KEY_DID_ERRORS: ErrorRegistryPart = {
  '1001': { category: 'key', retriable: false, message: 'BIP-39 ニーモニックが不正です' },
  '1002': {
    category: 'key',
    retriable: false,
    message: 'ワード数は 12 または 24 を指定してください',
  },
  '1003': { category: 'key', retriable: false, message: '秘密鍵フォーマットが不正です' },
  '1004': { category: 'key', retriable: false, message: '指定された鍵が見つかりません' },
  // 鍵がロック中（PIN + 生体認証によるアンロック前）。再アンロックで解消するため再試行不可扱い。
  '1005': { category: 'key', retriable: false, message: '鍵がロックされています' },
  '1020': { category: 'key', retriable: false, message: '署名演算に失敗しました' },
  // チェーン送信失敗 / RPC 呼び出し失敗（ガス不足 / ガス見積もり失敗 / ブロードキャスト失敗 / eth_call エラー・戻り値不正含む）。
  // ネットワーク要因が主因のため再試行可能とする。
  '1021': { category: 'key', retriable: true, message: 'チェーンへの送信に失敗しました' },
  '1030': { category: 'key', retriable: false, message: '未対応のアルゴリズムです' },
  '1040': { category: 'key', retriable: false, message: '不正な BIP-44 導出パスです' },
  '1041': { category: 'key', retriable: false, message: 'マスターシードが初期化されていません' },
  '1042': { category: 'key', retriable: false, message: 'ニーモニックが存在しません' },
  '1043': {
    category: 'key',
    retriable: false,
    message: '既にニーモニックが永続化されています（上書きには明示的な指定が必要です）',
  },
  '1050': { category: 'key', retriable: false, message: '復号に失敗しました' },
  '1051': { category: 'key', retriable: false, message: '暗号化に失敗しました' },
  '1011': { category: 'key', retriable: false, message: 'SLIP-0039 エンコードに失敗しました' },
  '1012': { category: 'key', retriable: false, message: 'シェア数が閾値未満です' },
  '1013': { category: 'key', retriable: false, message: 'シェア間のグループが一致しません' },
  '1014': { category: 'key', retriable: false, message: 'シェアのチェックサム検証に失敗しました' },
  '1015': { category: 'key', retriable: false, message: 'threshold / total が不正です' },
  '1022': { category: 'key', retriable: false, message: '有効な ECDSA Validator が存在しません' },
  '1031': { category: 'key', retriable: false, message: 'PIN ポリシーに適合しません' },
  '1032': { category: 'key', retriable: false, message: 'Passkey の作成に失敗しました' },
  '1033': { category: 'key', retriable: false, message: 'WUA の再発行に失敗しました' },
  '2001': { category: 'did', retriable: false, message: 'DID 文字列形式が不正です' },
  '2002': { category: 'did', retriable: false, message: '未対応の DID メソッドです' },
  // 2003 は取得失敗（network / タイムアウト / 4xx・5xx）が主因のため再試行可能とする。
  '2003': { category: 'did', retriable: true, message: 'DID を解決できませんでした' },
  '2005': { category: 'did', retriable: false, message: '指定されたペルソナが見つかりません' },
  // controller 未設定 / 自身が controller でない（権限・設定の問題のため再試行不可）。
  '2006': { category: 'did', retriable: false, message: 'controller の権限がありません' },
  // 指定 DID に対応する署名鍵が解決できない（アクティブペルソナ未設定 / DID 不一致 / シード未投入）。
  // 鍵・ペルソナの設定の問題であり再試行しても解消しないため再試行不可。
  '2007': { category: 'did', retriable: false, message: 'DID の署名鍵が利用できません' },
  '2008': { category: 'did', retriable: false, message: '同一 index のペルソナが既に存在します' },
  '2010': { category: 'did', retriable: false, message: 'DID ドキュメントが不正です' },
  // content-addressed DID / VC claim の contentHash と実コンテンツの不一致。
  // Artifact すり替えの検知シグナルであり、再試行しても解消しないため再試行不可。
  '2009': { category: 'did', retriable: false, message: 'contentHash が一致しません' },
  // contentHash 表記が未対応（未知アルゴリズム・不正エンコード・ダイジェスト長不一致）。
  '2016': { category: 'did', retriable: false, message: 'contentHash の表記が不正です' },
  // 保持鍵が DID Document の検証メソッド（要求した検証関係）と一致しない。DID 側の修正が要るため再試行不可。
  '2017': {
    category: 'did',
    retriable: false,
    message: '保持している鍵が DID Document の検証メソッドと一致しません',
  },
  // controller 連鎖に閉路があり所有者を確定できない（設定ミスのため再試行不可）。
  '2030': { category: 'did', retriable: false, message: 'controller の循環参照を検出しました' },
};
