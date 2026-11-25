/**
 * Core SDK のセマンティックバージョン。package.json の version と同期する。
 *
 * 将来的に wallet / storage などの公開モジュールをこのエントリポイントから
 * re-export する想定。
 */
export const SDK_VERSION = '0.1.0' as const;

// 公開 API はドメイン別 sub-barrel（./exports/*）に分割し、
// このエントリポイントはそれらを束ねるだけの薄い barrel とする。
// /asset の personalSignMessageBytes はサブパス専用なので、メインの公開名を明示する。
export type {
  AbiCodec,
  AssetChain,
  BuildTransferTxDeps,
  Erc20ReadDeps,
  Erc721ReadDeps,
  Erc1155ReadDeps,
  EvmCallRequest,
  EvmCallSource,
  SignAndSendDeps,
  StrictSiweFields,
  TransactionRequest,
  TxSerializer,
  TypedData,
  TypedDataField,
} from './exports/asset.js';
export {
  ASSET_CHAIN_IDS,
  assertPersonalSignAllowed,
  buildTransferTx,
  createErc20AbiCodec,
  createErc721AbiCodec,
  createErc1155AbiCodec,
  createEthersCallSource,
  createLegacyTxSerializer,
  createTxSerializer,
  encodeType,
  formatEthereumSignature,
  getErc721Balance,
  getErc721Owner,
  getErc721TokenUri,
  getErc1155Balance,
  getErc1155BalanceBatch,
  getErc1155Uri,
  getTokenBalance,
  getTokenDecimals,
  getTokenSymbol,
  isHexString,
  isSupportedChainId,
  isValidEvmAddress,
  NATIVE_TOKEN_ADDRESS,
  ownsErc721Token,
  parseSiweStrict,
  personalSignPayload,
  resolveChainId,
  resolveChainName,
  signAndSendTransaction,
  signSIWE,
  typedDataV4Payload,
} from './exports/asset.js';
export * from './exports/auth.js';
export * from './exports/cache.js';
export * from './exports/credential.js';
export * from './exports/delegated-did.js';
export * from './exports/delegation.js';
export * from './exports/did-signing.js';
export * from './exports/didcomm.js';
export * from './exports/errors.js';
export * from './exports/eudi.js';
export * from './exports/failsafe.js';
export * from './exports/gdpr.js';
export * from './exports/identity.js';
export * from './exports/interop.js';
export * from './exports/issuer.js';
export * from './exports/keymanager.js';
export * from './exports/persona.js';
export * from './exports/trust.js';
export * from './exports/trusted-issuer.js';
export * from './exports/wallet.js';
export * from './exports/wallet-migration.js';
