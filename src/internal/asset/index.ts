/**
 * asset モジュール（ERC-20 残高取得 / 送金 Tx 構築・署名・送信 / ERC-721・ERC-1155 の照会）の
 * 内部バレル。
 *
 * 対応ネットワークの解決、ネイティブ資産と ERC-20 の残高取得、ERC-721 / ERC-1155 の照会、
 * ERC-20 送金のトランザクション構築・署名・送信を提供する。
 *
 * - rpc.ts:            RPC アクセス seam（EvmCallSource：eth_call / eth_getBalance / gas・nonce 取得 / send）。
 * - codec.ts:          ABI エンコード/デコード seam（AbiCodec）。
 * - read-utils.ts:     read 系共有のアドレス検証・戻り値デコード正規化（assertAddress ほか）。
 * - chains.ts:         対応チェーン（Mainnet / Arbitrum / Soneium / Filecoin FEVM）と chainId 解決。
 * - erc20.ts: ERC-20 残高・decimals・symbol 取得。
 * - erc20-tx.ts: ERC-20 送金 Tx 構築・署名・送信（TxSerializer seam を含む）。
 * - erc721.ts: ERC-721 残高・所有判定・tokenURI 取得。
 * - erc1155.ts: ERC-1155 残高・一括残高・uri 取得。
 * - ethers-adapter.ts: ethers を隔離した各 seam の既定実装（createErc20AbiCodec ほか）。
 * - rlp.ts / legacy-tx-serializer.ts: ethers 非依存の RLP・legacy Tx `TxSerializer`（
 *   extension が ethers をバンドルしない方針のため、`createTxSerializer` の代替として使う）。
 * - eth-signing.ts:    `personal_sign` / `eth_signTypedData_v4` の署名対象バイト列組み立てと
 *   署名 hex 整形。
 *
 * SDK facade（wallet.ts / index.ts）への配線・getNFTs 組み立ては別スコープであり本バレルには含めない。
 */

export type { AssetChain } from './chains.js';
export {
  ASSET_CHAIN_IDS,
  isSupportedChainId,
  resolveChainId,
  resolveChainName,
} from './chains.js';
export type { AbiCodec } from './codec.js';
export {
  type Erc20ReadDeps,
  getTokenBalance,
  getTokenDecimals,
  getTokenSymbol,
  NATIVE_TOKEN_ADDRESS,
} from './erc20.js';
export {
  type BuildTransferTxDeps,
  buildTransferTx,
  type SignAndSendDeps,
  signAndSendTransaction,
  type TransactionRequest,
  type TxSerializer,
} from './erc20-tx.js';
export {
  type Erc721ReadDeps,
  getErc721Balance,
  getErc721Owner,
  getErc721TokenUri,
  ownsErc721Token,
} from './erc721.js';
export {
  type Erc1155ReadDeps,
  getErc1155Balance,
  getErc1155BalanceBatch,
  getErc1155Uri,
} from './erc1155.js';
export { formatEthereumSignature, personalSignPayload, typedDataV4Payload } from './eth-signing.js';
export { encodeType, type TypedData, type TypedDataField } from './eth-typed-data-types.js';
export {
  createErc20AbiCodec,
  createErc721AbiCodec,
  createErc1155AbiCodec,
  createEthersCallSource,
  createEvmCallSource,
  createTxSerializer,
} from './ethers-adapter.js';
export { createLegacyTxSerializer } from './legacy-tx-serializer.js';
export type {
  EvmCallRequest,
  EvmCallSource,
  EvmSendRequest,
  EvmTxEstimate,
  EvmTxParams,
} from './rpc.js';
