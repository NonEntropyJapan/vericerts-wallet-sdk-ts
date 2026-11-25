/**
 * `ModularAccount` / `EntryPoint` の最小 ABI エンコード/デコード（緊急 Validator 失効）。
 *
 * `ModularAccount` の `getValidators` / `uninstallValidator` / `execute` /
 * `executeBatch`、および ERC-4337 v0.7 EntryPoint の `getNonce` のみを対象にする。既存の `asset/ethers-adapter.ts` / `delegation/ethers-adapter.ts`
 * と同様、ethers を隔離する adapter として本ファイルのみが ethers に依存する。
 */

import { AbiCoder, Interface } from 'ethers';
import type { AbiCodec } from '../asset/codec.js';
import { ErrorCodes, VericertsError } from '../errors.js';
import type { Hex } from './types.js';

/** 本モジュールが対象とする ABI（人間可読フラグメント）。 */
const MODULAR_ACCOUNT_ABI = [
  'function getValidators() view returns (address[])',
  'function validatorWeight(address validator) view returns (uint256)',
  'function threshold() view returns (uint256)',
  'function uninstallValidator(address validator, bytes data)',
  'function execute(address dest, uint256 value, bytes func) returns (bytes)',
  'function executeBatch(address[] dest, uint256[] value, bytes[] func) returns (bytes[])',
] as const;

const ENTRY_POINT_ABI = [
  'function getNonce(address sender, uint192 key) view returns (uint256)',
] as const;

/**
 * ModularAccount の calldata エンコード/デコードを提供する `AbiCodec`。
 *
 * `asset/ethers-adapter.ts` の `createAbiCodec`（非公開）と同一パターン。encode/decode の例外は
 * cause を渡さず正規化する（引数・戻り値にアドレス・calldata が含まれ得るため）。
 */
export function createModularAccountAbiCodec(): AbiCodec {
  const iface = new Interface(MODULAR_ACCOUNT_ABI);
  return {
    encode(functionName: string, args: readonly unknown[]): string {
      try {
        return iface.encodeFunctionData(functionName, args as unknown[]);
      } catch {
        throw new VericertsError(ErrorCodes.INVALID_EVM_ADDRESS);
      }
    },
    decode(functionName: string, data: string): readonly unknown[] {
      try {
        return iface.decodeFunctionResult(functionName, data) as unknown as readonly unknown[];
      } catch {
        throw new VericertsError(ErrorCodes.CHAIN_SUBMIT_FAILED);
      }
    },
  };
}

/** EntryPoint の calldata エンコード/デコードを提供する `AbiCodec`（`getNonce` のみ）。 */
export function createEntryPointAbiCodec(): AbiCodec {
  const iface = new Interface(ENTRY_POINT_ABI);
  return {
    encode(functionName: string, args: readonly unknown[]): string {
      try {
        return iface.encodeFunctionData(functionName, args as unknown[]);
      } catch {
        throw new VericertsError(ErrorCodes.INVALID_EVM_ADDRESS);
      }
    },
    decode(functionName: string, data: string): readonly unknown[] {
      try {
        return iface.decodeFunctionResult(functionName, data) as unknown as readonly unknown[];
      } catch {
        throw new VericertsError(ErrorCodes.CHAIN_SUBMIT_FAILED);
      }
    },
  };
}

/**
 * `ECDSAValidator.validateSignature` が要求する単一 Validator 形式の UserOperation 署名を組み立てる
 * （`abi.encode(address validator, bytes innerSig)`。`ERC4337Account.decodeSignature` 参照）。
 *
 * `innerSig` は 65 バイト `r(32) || s(32) || v(1)`。`v` はイーサリアム互換の 27/28
 * （`signSecp256k1Recoverable` の `recovery`（0/1）に 27 を加算した値、`ECDSAValidator._validate`
 * が `v ∈ {27,28}` のみ許可するため）。
 *
 * @param validatorAddress 署名に用いる ECDSAValidator インスタンスのアドレス。
 * @param signature secp256k1 recoverable 署名（`r(32)||s(32)||recovery(1)`、65 バイト）。
 * @param recovery recovery id（0 または 1）。
 * @returns UserOperation の `signature` フィールドに設定する hex。
 */
export function encodeValidatorSignature(
  validatorAddress: string,
  signature: Uint8Array,
  recovery: number,
): Hex {
  const rs = signature.slice(0, 64);
  const v = recovery + 27;
  const innerSig = new Uint8Array(65);
  innerSig.set(rs, 0);
  innerSig[64] = v;
  const encoded = AbiCoder.defaultAbiCoder().encode(
    ['address', 'bytes'],
    [validatorAddress, innerSig],
  );
  return encoded as Hex;
}
