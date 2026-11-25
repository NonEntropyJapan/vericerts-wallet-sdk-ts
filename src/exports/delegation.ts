export type {
  AbiEncoder,
  ControllerTxDeps,
  EthrDidParts,
  UnsignedTransaction,
} from '../internal/delegation/index.js';
export {
  buildRemoveControllerTx,
  buildSetControllerTx,
  createErc1056AbiEncoder,
  createEthersEventSource,
  detectController,
  formatEthrDid,
  parseEthrDid,
} from '../internal/delegation/index.js';
