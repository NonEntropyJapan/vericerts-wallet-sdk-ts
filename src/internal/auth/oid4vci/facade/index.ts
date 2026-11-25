/**
 * ファサード `receiveCredential` の内部バレル。
 *
 * - types.ts:   受領 API の入出力型（`ReceivedVerifiableCredential` / `ReceiveCredentialDeps`）と、
 *               `issuer/module/issue-options.ts` に集約した `VCFormat` の再輸出。
 * - deps.ts:    呼び出し側依存の own 限定読みと検証。
 * - decode.ts:  受領した生 VC を 受領結果へ変換する。
 * - receive.ts: Offer → Metadata → grant 振り分け → 受領 → 解釈のオーケストレーション。
 */

export { toReceivedCredential } from './decode.js';
export { receiveCredential } from './receive.js';
export type {
  ReceiveCredentialDeps,
  ReceivedVerifiableCredential,
  VCFormat,
} from './types.js';
