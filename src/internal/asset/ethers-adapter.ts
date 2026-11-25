/**
 * asset モジュール（残高取得 / 送金 Tx / NFT 一覧取得）の ethers 依存を隔離する
 * 既定実装アダプタ。
 *
 * 本ファイル「のみ」が asset 配下で ethers に依存し、コア（erc20.ts / erc20-tx.ts / erc721.ts /
 * erc1155.ts）は `AbiCodec` / `EvmCallSource` / `TxSerializer` の各 seam を介してのみ ethers に
 * 触れる（identity/ethr/registry.ts・delegation/ethers-adapter.ts と同様の ethers 隔離方針）。
 *
 * 提供物:
 * - `createErc20AbiCodec`: ERC-20 read ABI（balanceOf / decimals / symbol）と `transfer` の
 *   calldata エンコード / 戻り値デコード（`ethers.Interface`）。
 * - `createErc721AbiCodec`: ERC-721 read ABI の calldata エンコード / 戻り値デコード（`ethers.Interface`）。
 * - `createErc1155AbiCodec`: ERC-1155 read ABI の calldata エンコード / 戻り値デコード（`ethers.Interface`）。
 * - `createEthersCallSource` / `createEvmCallSource`: eth_call / eth_getBalance（読み取り）と
 *   gas・nonce 取得 / 署名済み生 Tx のブロードキャストを行う `EvmCallSource`。ethers の `JsonRpcProvider` は使わず
 *   `bounded-rpc/call-source.ts`（`requestJsonRpc`: 10 秒・1 MiB）へ委譲する。
 *   両者は同一の実装を返す（互換のため別名を提供する）。
 * - `createTxSerializer`: 未署名 legacy Tx の RLP シリアライズと署名組み立て（`ethers.Transaction`）。
 *
 * セキュリティ上の注意:
 * - RPC URL・アドレス・金額・残高・tokenId・署名済み Tx・引数値を例外 message / context / cause に
 *   伝播させない。ethers / RPC 由来例外は cause を渡さず VericertsError に正規化する。
 */

import { getBytes, hexlify, Interface, Signature, Transaction } from 'ethers';
import { ErrorCodes, VericertsError } from '../errors.js';
import { createBoundedRpcCallSource, type RpcUrls } from './bounded-rpc/call-source.js';
import type { AbiCodec } from './codec.js';
import type { TransactionRequest, TxSerializer } from './erc20-tx.js';
import type { EvmCallSource } from './rpc.js';

/** legacy（EIP-155）トランザクションタイプ。 */
const TX_TYPE_LEGACY = 0;

/** recoverable 署名（r||s||v）の固定長（バイト）。 */
const RECOVERABLE_SIG_LENGTH = 65;

/**
 * ERC-20 の最小 ABI。read 系（残高取得・メタデータ取得）と `transfer`（送金）を含む。
 */
const ERC20_ABI = [
  'function balanceOf(address owner) view returns (uint256)',
  'function decimals() view returns (uint8)',
  'function symbol() view returns (string)',
  'function transfer(address to, uint256 amount) returns (bool)',
] as const;

/**
 * ERC-721 の最小 ABI（残高・所有判定・メタデータ取得に必要な read 関数のみ）。
 */
const ERC721_ABI = [
  'function balanceOf(address owner) view returns (uint256)',
  'function ownerOf(uint256 tokenId) view returns (address)',
  'function tokenURI(uint256 tokenId) view returns (string)',
] as const;

/**
 * ERC-1155 の最小 ABI（残高・一括残高・メタデータ取得に必要な read 関数のみ）。
 */
const ERC1155_ABI = [
  'function balanceOf(address account, uint256 id) view returns (uint256)',
  'function balanceOfBatch(address[] accounts, uint256[] ids) view returns (uint256[])',
  'function uri(uint256 id) view returns (string)',
] as const;

/**
 * 与えた ABI フラグメント列から `ethers.Interface` を用いた `AbiCodec` を生成する。
 *
 * encode/decode の例外は cause を渡さず VericertsError に正規化する（引数・戻り値に
 * アドレス・金額・tokenId・残高等が含まれ得るため）。
 *
 * @param abi 人間可読 ABI フラグメントの配列。
 * @returns `AbiCodec`。
 */
function createAbiCodec(abi: readonly string[]): AbiCodec {
  const iface = new Interface(abi);
  return {
    encode(functionName: string, args: readonly unknown[]): string {
      try {
        return iface.encodeFunctionData(functionName, args as unknown[]);
      } catch {
        // 引数（アドレス・金額・tokenId）が例外に含まれ得るため cause を渡さず正規化する。
        throw new VericertsError(ErrorCodes.INVALID_EVM_ADDRESS);
      }
    },
    decode(functionName: string, data: string): readonly unknown[] {
      try {
        const result = iface.decodeFunctionResult(functionName, data);
        return result as unknown as readonly unknown[];
      } catch {
        // 戻り値が想定外（コントラクト不在・revert 等）。RPC 系の失敗として正規化する。
        throw new VericertsError(ErrorCodes.CHAIN_SUBMIT_FAILED);
      }
    },
  };
}

/**
 * ERC-20 ABI に基づく既定 `AbiCodec` を生成する（erc20.ts / erc20-tx.ts に注入）。
 *
 * @returns `ethers.Interface` を用いた `AbiCodec`。
 */
export function createErc20AbiCodec(): AbiCodec {
  return createAbiCodec(ERC20_ABI);
}

/**
 * ERC-721 ABI に基づく既定 `AbiCodec` を生成する（erc721.ts に注入）。
 *
 * @returns `ethers.Interface` を用いた `AbiCodec`。
 */
export function createErc721AbiCodec(): AbiCodec {
  return createAbiCodec(ERC721_ABI);
}

/**
 * ERC-1155 ABI に基づく既定 `AbiCodec` を生成する（erc1155.ts に注入）。
 *
 * @returns `ethers.Interface` を用いた `AbiCodec`。
 */
export function createErc1155AbiCodec(): AbiCodec {
  return createAbiCodec(ERC1155_ABI);
}

/**
 * 既定の `EvmCallSource` を生成する（erc20.ts / erc20-tx.ts / erc721.ts / erc1155.ts に注入）。
 *
 * 読み取り（`call` / `nativeBalance`）と送金 Tx 用の gas・nonce 取得（`fetchTxParams`）・
 * ブロードキャスト（`send`）を `http/json-rpc.ts` の `requestJsonRpc`（10 秒・1 MiB・redirect 非追従）
 * 経由で行う（素の `JsonRpcProvider` は応答本文・時間に上限が無かった）。未設定チェーンは
 * `CHAIN_NOT_CONFIGURED`（4071）、RPC 由来の失敗・形状違反は cause を渡さず `CHAIN_SUBMIT_FAILED`（1021）。
 * 名前は互換のため `Ethers` を残すが、ethers の `JsonRpcProvider` には依存しない。
 *
 * @param rpcUrls チェーン ID → RPC URL マップ（Mainnet=1 / Arbitrum=42161 / Soneium=1868 等）。
 *                未設定チェーンは `CHAIN_NOT_CONFIGURED`。
 * @returns 本文・時間に上限のある `EvmCallSource`。
 */
export function createEthersCallSource(rpcUrls: RpcUrls): EvmCallSource {
  return createBoundedRpcCallSource(rpcUrls);
}

/**
 * `createEthersCallSource` の別名（送金経路からの互換参照）。同一の `EvmCallSource` を返す。
 *
 * @param rpcUrls チェーン ID → RPC URL マップ。未設定チェーンは `CHAIN_NOT_CONFIGURED`。
 * @returns `EvmCallSource`。
 */
export function createEvmCallSource(rpcUrls: RpcUrls): EvmCallSource {
  return createBoundedRpcCallSource(rpcUrls);
}

/**
 * 補完済み未署名トランザクションから ethers の legacy `Transaction` を組み立てる。
 *
 * @param tx 補完済み未署名トランザクション。
 * @returns type 0（legacy）の `ethers.Transaction`。
 */
function toEthersTransaction(tx: TransactionRequest): Transaction {
  return Transaction.from({
    type: TX_TYPE_LEGACY,
    to: tx.to,
    value: tx.value,
    data: tx.data,
    gasLimit: tx.gasLimit,
    gasPrice: tx.gasPrice,
    nonce: tx.nonce,
    chainId: tx.chainId,
  });
}

/**
 * ethers を用いた既定の `TxSerializer` 実装を生成する（erc20-tx.ts に注入）。
 *
 * legacy（type 0）トランザクションとしてシリアライズする。署名対象は `unsignedSerialized` の
 * バイト列であり、`Signer.sign` が keccak256 + secp256k1 recoverable 署名を計算する。
 *
 * @returns `ethers.Transaction` を用いた `TxSerializer`。
 */
export function createTxSerializer(): TxSerializer {
  return {
    serializeUnsigned(tx: TransactionRequest): Uint8Array {
      try {
        return getBytes(toEthersTransaction(tx).unsignedSerialized);
      } catch (cause) {
        void cause;
        throw new VericertsError(ErrorCodes.CHAIN_SUBMIT_FAILED);
      }
    },

    assembleSigned(tx: TransactionRequest, signature: Uint8Array): string {
      if (signature.length !== RECOVERABLE_SIG_LENGTH) {
        throw new VericertsError(ErrorCodes.CHAIN_SUBMIT_FAILED);
      }
      try {
        const ethersTx = toEthersTransaction(tx);
        // 65 バイト署名は r(32) || s(32) || recovery(0/1)。recovery を yParity として渡す。
        const r = hexlify(signature.subarray(0, 32));
        const s = hexlify(signature.subarray(32, 64));
        // 長さ 65 を確認済みのため index 64 は必ず存在する。recovery は 0/1 のみ許容する。
        const recovery = signature[64];
        if (recovery !== 0 && recovery !== 1) {
          throw new VericertsError(ErrorCodes.CHAIN_SUBMIT_FAILED);
        }
        ethersTx.signature = Signature.from({ r, s, yParity: recovery });
        return ethersTx.serialized;
      } catch (cause) {
        void cause;
        throw new VericertsError(ErrorCodes.CHAIN_SUBMIT_FAILED);
      }
    },
  };
}
