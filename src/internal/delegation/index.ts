/**
 * delegation モジュール（ERC-1056 controller 設定・削除・検出）の内部バレル。
 *
 * setController / removeController / getControlledDIDs の
 * 基盤を提供する。独自の委任証書（SubjectBinding / DelegationGrant）と代理署名（signAsDelegate）は
 *削除した。DID Core の `controller` に基づく委任は `internal/credential/did-signing/delegation.ts`
 * （`verifyDelegationControl` / `resolveDelegatedSigner`）が担う。
 *
 * - did-ethr.ts: did:ethr パース／組み立て（ethers 非依存）。
 * - tx.ts:        controller 設定／削除の未署名トランザクション構築（AbiEncoder シーム）。
 * - events.ts:    controller 検出・循環参照判定（ethr/registry.ts の Erc1056EventSource を再利用）。
 * - ethers-adapter.ts: ethers を隔離した既定の AbiEncoder（書き込み Tx 構築）実装。
 *
 * イベント取得シーム（`Erc1056EventSource` / `createEthersEventSource`）は did:ethrの
 * ethr/registry.ts を再利用し、events.ts 経由で再 export する。
 */

export { type EthrDidParts, formatEthrDid, parseEthrDid } from './did-ethr.js';
export { createErc1056AbiEncoder } from './ethers-adapter.js';
export {
  createEthersEventSource,
  detectController,
  type Erc1056EventSource,
} from './events.js';
export {
  type AbiEncoder,
  buildRemoveControllerTx,
  buildSetControllerTx,
  type ControllerTxDeps,
  type UnsignedTransaction,
} from './tx.js';
