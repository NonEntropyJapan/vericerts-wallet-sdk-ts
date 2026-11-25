/**
 * HAIP SD-JWT VC 相互運用テストのエントリ。
 *
 * HAIP SD-JWT VC 相互運用ペアハーネス（Offer → Receive → Present）と、共通テストベクター
 * （fixtures）・対象実装（Peer）記述子・マトリクススコープ判定を再エクスポートする。
 * `exports/interop.ts` を通じて外部の相互運用ドライバからも利用できる。
 */

export {
  credentialInput,
  foreignHolderSigner,
  HAIP_ALG,
  HOLDER_CNF,
  HOLDER_JWK,
  holderSigner,
  ISSUER_JWK,
  issuerSigner,
  VCT,
} from './fixtures.js';
export type { InteropPairInput, InteropPairResult } from './harness.js';
export { runInteropPair } from './harness.js';
export type { InteropRole, Peer, PeerId } from './peers.js';
export {
  interopTestName,
  PEERS,
  supportsRole,
} from './peers.js';
export type { InteropTxPairInput, InteropTxPairResult } from './tx-harness.js';
export { runInteropTxPair } from './tx-harness.js';
