/**
 * eudi/issuance モジュールの公開エントリ。
 *
 * OID4VCI Pre-Authorized Code Flow で PID / (Q)EAA を受領する内部フローを再エクスポートする。
 * 本モジュールは内部プリミティブで、Wallet facade（`receivePID` / `receiveEAA`）への配線は
 * `wallet/eudi/facade.ts` が担う。`exports/` へ出しているのは利用者が型で受け取る必要のある
 * ものだけである。
 *
 * `eudi/pid` が「受領済みの PID / (Q)EAA の型定義とスキーマ検証・Catalogue 参照」だけを担い、
 * 受領そのものの手続き（通信・Proof 生成・受領後検証）を持たないため、その手続きを本モジュールに
 * 分けている。Wallet は PID を受領する。PID の発行は発行者の責務である。
 */

export {
  assertPIDSchemaValid,
  type DecodedCredential,
  decodeReceivedCredential,
} from './decode.js';
export { fetchIssuerMetadata, type IssuerEndpoints } from './metadata.js';
export { receiveEAACredential, receivePIDCredential } from './receive.js';
export type { ReceiveDeps } from './types.js';
