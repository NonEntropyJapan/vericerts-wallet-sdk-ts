/**
 * 9xxx DIDComm v2 のエラー定義（schemas/error-codes.json）。
 *
 * `message` には秘密情報を一切含めない。
 */

import type { ErrorRegistryPart } from './definition.js';

/** 9xxx（didcomm）のコード → 定義。 */
export const DIDCOMM_ERRORS: ErrorRegistryPart = {
  // Authcrypt/Anoncrypt 失敗。主因は相手 DID 解決失敗（形式不正 / 未登録メソッド / 未解決）。
  // DID 自体の是正が必要なため再試行不可。
  '9001': { category: 'didcomm', retriable: false, message: 'メッセージの暗号化に失敗しました' },
  // 復号失敗。主因は鍵不一致（keyAgreement 鍵のローテーション等）。再試行では解決しないため不可。
  '9002': { category: 'didcomm', retriable: false, message: 'メッセージの復号に失敗しました' },
  // メッセージパッキング失敗。主因は受信者鍵不一致（非対応曲線等）/ エンコードエラー。
  // 送信先 DID・鍵の是正が必要なため再試行不可。
  '9003': {
    category: 'didcomm',
    retriable: false,
    message: 'メッセージのパッキングに失敗しました',
  },
  '9004': {
    category: 'didcomm',
    retriable: false,
    message: 'メッセージのアンパッキングに失敗しました',
  },
  // Invitation URI のパース失敗。主因は不正な URI / base64url 形式。再発行が必要なため再試行不可。
  '9005': {
    category: 'didcomm',
    retriable: false,
    message: 'Invitation URI のパースに失敗しました',
  },
  '9010': { category: 'didcomm', retriable: false, message: 'OOB Invitation が不正です' },
  // Mediator 到達不能。主因は HTTP エラー（ネットワーク要因）のため再試行可能。
  '9020': { category: 'didcomm', retriable: true, message: 'Mediator に到達できませんでした' },
  // serviceEndpoint が見つからない。相手 DID Document の設定不備のため再試行不可。
  '9030': {
    category: 'didcomm',
    retriable: false,
    message: 'serviceEndpoint が見つかりませんでした',
  },
};
