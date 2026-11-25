/**
 * ethers 非依存の legacy（EIP-155）トランザクション `TxSerializer`。
 *
 * ethers / viem / permissionless を含まないバンドルでも使えるよう、
 * `ethers-adapter.ts` の `createTxSerializer` に依存しない。
 * 本モジュールは RLP（`rlp.ts`）のみに依存し、legacy 形式（type 0、EIP-155 リプレイ保護）の
 * 未署名 Tx シリアライズ・署名済み生 Tx 組み立てを提供する。`erc20-tx.ts` の `TxSerializer` と
 * 構造的に同じ契約を満たすため、`buildTransferTx` / `signAndSendTransaction` へそのまま注入できる。
 *
 * 署名対象バイト列（`serializeUnsigned`）は EIP-155 の定義に厳密に従う:
 * `rlp([nonce, gasPrice, gasLimit, to, value, data, chainId, 0, 0])`。
 * `Signer.sign` がこのバイト列を keccak256 してから secp256k1 recoverable 署名するため、
 * 結果は EVM の署名ハッシュと一致する（`erc20-tx.ts` の docblock と同じ前提）。
 *
 * `v` は EIP-155 のリプレイ保護規則（`chainId * 2 + 35 + recovery`）で計算する。
 */

import { ErrorCodes, VericertsError } from '../errors.js';
import { isHexString } from '../evm-format.js';
import type { TransactionRequest, TxSerializer } from './erc20-tx.js';
import { bytesToHex, decodeHexDigits } from './hex-codec.js';
import { bigIntToMinimalBytes, rlpEncode, stripLeadingZeros } from './rlp.js';

const RECOVERABLE_SIGNATURE_LENGTH = 65;
const R_LENGTH = 32;
const S_END = 64;

/**
 * `0x` プレフィックス付き hex 文字列をバイト列へ変換する。
 *
 * `0x` の有無は `evm-format.ts` の SSOT（{@link isHexString}）で検証し、プレフィックス無しの
 * 生 hex 文字列（桁数・パターンのみ一致するもの）は拒否する（`eth-signing.ts` と同じ方針）。
 */
function hexToBytes(hex: string): Uint8Array {
  if (!isHexString(hex, { allowEmpty: true })) {
    throw new VericertsError(ErrorCodes.CHAIN_SUBMIT_FAILED);
  }
  const normalized = hex.slice(2);
  if (normalized.length % 2 !== 0) {
    throw new VericertsError(ErrorCodes.CHAIN_SUBMIT_FAILED);
  }
  return decodeHexDigits(normalized);
}

/**
 * `to`（`0x` + 40 hex のトークンコントラクトアドレス）を RLP バイト文字列へ変換する。
 *
 * 空文字（contract creation）は受け付けない。`TransactionRequest` は ERC-20 transfer 専用で作成 Tx を
 * 表さないため、`to = ''` を許すと `tokenAddress` 欠落が calldata を init code とする作成 Tx として
 * 署名・送信される。
 */
function encodeTo(to: string): Uint8Array {
  const bytes = hexToBytes(to);
  if (bytes.length !== 20) {
    throw new VericertsError(ErrorCodes.CHAIN_SUBMIT_FAILED);
  }
  return bytes;
}

function unsignedFields(tx: TransactionRequest): readonly Uint8Array[] {
  return [
    bigIntToMinimalBytes(BigInt(tx.nonce)),
    bigIntToMinimalBytes(tx.gasPrice),
    bigIntToMinimalBytes(tx.gasLimit),
    encodeTo(tx.to),
    bigIntToMinimalBytes(tx.value),
    hexToBytes(tx.data),
  ];
}

/**
 * ethers 非依存の既定 `TxSerializer` 実装（legacy / EIP-155）。
 *
 * @returns `serializeUnsigned` / `assembleSigned` を実装した `TxSerializer`。
 */
export function createLegacyTxSerializer(): TxSerializer {
  return {
    serializeUnsigned(tx: TransactionRequest): Uint8Array {
      try {
        return rlpEncode([
          ...unsignedFields(tx),
          bigIntToMinimalBytes(BigInt(tx.chainId)),
          new Uint8Array(0),
          new Uint8Array(0),
        ]);
      } catch (cause) {
        if (cause instanceof VericertsError) throw cause;
        throw new VericertsError(ErrorCodes.CHAIN_SUBMIT_FAILED);
      }
    },
    assembleSigned(tx: TransactionRequest, signature: Uint8Array): string {
      if (signature.length !== RECOVERABLE_SIGNATURE_LENGTH) {
        throw new VericertsError(ErrorCodes.CHAIN_SUBMIT_FAILED);
      }
      const recovery = signature[S_END] as number;
      if (recovery !== 0 && recovery !== 1) {
        throw new VericertsError(ErrorCodes.CHAIN_SUBMIT_FAILED);
      }
      try {
        const r = stripLeadingZeros(signature.subarray(0, R_LENGTH));
        const s = stripLeadingZeros(signature.subarray(R_LENGTH, S_END));
        const v = BigInt(tx.chainId) * 2n + 35n + BigInt(recovery);
        const encoded = rlpEncode([...unsignedFields(tx), bigIntToMinimalBytes(v), r, s]);
        return bytesToHex(encoded);
      } catch (cause) {
        if (cause instanceof VericertsError) throw cause;
        throw new VericertsError(ErrorCodes.CHAIN_SUBMIT_FAILED);
      }
    },
  };
}
