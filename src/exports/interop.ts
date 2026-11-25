/**
 * HAIP SD-JWT VC の Offer → Receive → Present を対象実装のペアで検証するための API。
 * 共通テストベクターと、各実装（Peer）がサポートするロールの情報も提供する。
 */

export type {
  InteropPairInput,
  InteropPairResult,
  InteropRole,
  InteropTxPairInput,
  InteropTxPairResult,
  Peer,
  PeerId,
} from '../internal/interop/index.js';
export {
  credentialInput,
  foreignHolderSigner,
  HAIP_ALG,
  HOLDER_CNF,
  HOLDER_JWK,
  holderSigner,
  ISSUER_JWK,
  interopTestName,
  issuerSigner,
  PEERS,
  runInteropPair,
  runInteropTxPair,
  supportsRole,
  VCT,
} from '../internal/interop/index.js';
