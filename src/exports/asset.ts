import { personalSignMessageBytes as personalSignMessageBytesImpl } from '../internal/asset/personal-sign-message.js';
import { markExperimental } from '../internal/experimental-warning.js';

// 承認前ガード。署名時ガード（`personalSignPayload`）と同じ判定を共有するため、定義元の eth-signing から直接出す。
export { assertPersonalSignAllowed } from '../internal/asset/eth-signing.js';
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
  TransactionRequest,
  TxSerializer,
  TypedData,
  TypedDataField,
} from '../internal/asset/index.js';
export {
  ASSET_CHAIN_IDS,
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
  isSupportedChainId,
  NATIVE_TOKEN_ADDRESS,
  ownsErc721Token,
  personalSignPayload,
  resolveChainId,
  resolveChainName,
  signAndSendTransaction,
  typedDataV4Payload,
} from '../internal/asset/index.js';
// personal-sign-message / SIWE / evm-format は `../internal/auth/index.js` 経由にせず
// 定義元を直接指す。auth バレルは `siwe/siwe.ts` 経由で `viem/siwe` を引き、ESM 出力（`--splitting`）で
// `/asset` のチャンクへ viem が入ってしまうため（ESM の `/asset` は viem を持たない。CJS は全サーフェス
// 共有の `_shared.cjs` を読むので、この分離は効かない。`exports/oid4vp.ts` が `auth/dcql/budget.js` を
// 直接指すのと同じ）。`signSIWE` は `exports/auth.ts` にも既にあるが、`./auth` は package.json の
// exports に無く利用者が引けない。移行先 entry を `/asset` と定めたレジストリに合わせて重複して
// 公開する。同一宣言に解決されるので `export *` で曖昧にならない（メインバレルとも同一参照）。
/**
 * `personal_sign` の `params[0]` を EIP-191 prefix を付ける前のメッセージバイト列に正規化する。
 * 偶数桁の `0x` hex はバイト列に復号し、それ以外は入力を UTF-8 でエンコードする。
 *
 * @experimental
 */
export const personalSignMessageBytes: (data: string) => Uint8Array = markExperimental(
  'personalSignMessageBytes',
  personalSignMessageBytesImpl,
  'node-process',
);
export { signSIWE } from '../internal/auth/siwe/siwe-sign.js';
export type { StrictSiweFields } from '../internal/auth/siwe/siwe-strict-parse.js';
export { parseSiweStrict } from '../internal/auth/siwe/siwe-strict-parse.js';
export { isHexString, isValidEvmAddress } from '../internal/evm-format.js';
