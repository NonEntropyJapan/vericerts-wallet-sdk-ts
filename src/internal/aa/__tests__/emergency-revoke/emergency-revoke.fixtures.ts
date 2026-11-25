/**
 * `emergencyRevoke` ユニットテストの共有フィクスチャ（fake EvmCallSource / BundlerRpc）。
 * 実 RPC・実チェーン非依存（aa/ 配下の既存モジュールと同じ方針、bundler.test.ts 参照）。
 *
 * テスト本体（`emergency-revoke.test.ts`）から分離してあるのは 1 ファイル 300 行の上限のため。
 */

import { Interface } from 'ethers';
import type { EvmCallRequest, EvmCallSource } from '../../../asset/rpc.js';
import type { BundlerRpc } from '../../bundler.js';
import { ENTRY_POINT_V07_ADDRESS, type Hex, type UserOperationV07 } from '../../types.js';
import { getUserOpHash } from '../../user-operation.js';

export const ACCOUNT = '0x100000000000000000000000000000000000000a' as Hex;
export const SIGNING_VALIDATOR = '0x200000000000000000000000000000000000000b' as Hex;
export const OTHER_VALIDATOR = '0x300000000000000000000000000000000000000c' as Hex;
export const TX_HASH = `0x${'aa'.repeat(32)}` as Hex;
export const USER_OP_HASH = `0x${'bb'.repeat(32)}` as Hex;
export const CHAIN_ID = 1;
export const SIGNER_WEIGHT = 1n;
export const THRESHOLD = 1n;

export const MODULAR_ACCOUNT_IFACE = new Interface([
  'function getValidators() view returns (address[])',
  'function validatorWeight(address validator) view returns (uint256)',
  'function threshold() view returns (uint256)',
  'function uninstallValidator(address validator, bytes data)',
  'function execute(address dest, uint256 value, bytes func) returns (bytes)',
  'function executeBatch(address[] dest, uint256[] value, bytes[] func) returns (bytes[])',
]);
const ENTRY_POINT_IFACE = new Interface([
  'function getNonce(address sender, uint192 key) view returns (uint256)',
]);

/**
 * `getValidators` の最初の読み出し（送信前）は `validators` を、以降（レシート確認後の読み直し）は
 * `postRevokeValidators` を返す。既定は「Bundler が UserOperation を実際に実行し、署名 Validator 以外が
 * 失効した」状態。悪意ある Bundler（実行せずレシートだけ偽造）は `postRevokeValidators: validators` で表す。
 */
export function fakeCallSource(
  validators: readonly string[],
  weights: {
    signerWeight?: bigint;
    threshold?: bigint;
    postRevokeValidators?: readonly string[];
  } = {},
): EvmCallSource {
  let validatorReads = 0;
  return {
    async call(request: EvmCallRequest): Promise<string> {
      if (request.to === ACCOUNT) {
        const parsed = MODULAR_ACCOUNT_IFACE.parseTransaction({ data: request.data });
        if (parsed?.name === 'getValidators') {
          const afterExecution = validatorReads++ > 0;
          const current = afterExecution
            ? (weights.postRevokeValidators ?? validators.filter((v) => v === SIGNING_VALIDATOR))
            : validators;
          return MODULAR_ACCOUNT_IFACE.encodeFunctionResult('getValidators', [current]);
        }
        if (parsed?.name === 'validatorWeight') {
          return MODULAR_ACCOUNT_IFACE.encodeFunctionResult('validatorWeight', [
            weights.signerWeight ?? SIGNER_WEIGHT,
          ]);
        }
        if (parsed?.name === 'threshold') {
          return MODULAR_ACCOUNT_IFACE.encodeFunctionResult('threshold', [
            weights.threshold ?? THRESHOLD,
          ]);
        }
        throw new Error(`unexpected function call: ${parsed?.name}`);
      }
      if (request.to === ENTRY_POINT_V07_ADDRESS) {
        return ENTRY_POINT_IFACE.encodeFunctionResult('getNonce', [7n]);
      }
      throw new Error(`unexpected call target: ${request.to}`);
    },
    async nativeBalance(): Promise<bigint> {
      throw new Error('not used in this test');
    },
    async fetchTxParams(): Promise<never> {
      throw new Error('not used in this test');
    },
    async send(): Promise<string> {
      throw new Error('not used in this test');
    },
  };
}

/**
 * 送られてきた hexlify 済み UserOperation を `UserOperationV07` へ戻す。
 *
 * 実 Bundler は受け取った UserOperation そのもののハッシュを返すので、fake もそう振る舞わせる
 * （固定値を返す fake だと、実装がどの UserOperation を送ったかに関わらずレシートが引けてしまい、
 * `userOpHash` の照合が入ったこと自体をテストが検知できない）。
 */
function fromRpcUserOperation(sent: Record<string, unknown>): UserOperationV07 {
  const hex = (key: string): Hex => sent[key] as Hex;
  const big = (key: string): bigint => BigInt(sent[key] as string);
  return {
    sender: hex('sender'),
    nonce: big('nonce'),
    callData: hex('callData'),
    callGasLimit: big('callGasLimit'),
    verificationGasLimit: big('verificationGasLimit'),
    preVerificationGas: big('preVerificationGas'),
    maxFeePerGas: big('maxFeePerGas'),
    maxPriorityFeePerGas: big('maxPriorityFeePerGas'),
    signature: hex('signature'),
  };
}

export function fakeBundlerRpc(
  receiptSuccess: boolean | null,
  onSend?: (userOp: Record<string, unknown>) => void,
  /** 実 Bundler と食い違うハッシュを返させる異常系用（既定は送られた UserOperation の実ハッシュ）。 */
  overrideSentHash?: Hex,
  /** レシートだけ別 UserOperation のものを返させる異常系用（既定は要求した UserOperation の hash）。 */
  overrideReceiptHash?: Hex,
): BundlerRpc {
  let sentHash: Hex = USER_OP_HASH;
  return {
    async request(method: string, params: readonly unknown[]): Promise<unknown> {
      switch (method) {
        case 'eth_estimateUserOperationGas':
          return { preVerificationGas: '0x1', verificationGasLimit: '0x2', callGasLimit: '0x3' };
        case 'eth_sendUserOperation': {
          const sent = params[0] as Record<string, unknown>;
          onSend?.(sent);
          sentHash = overrideSentHash ?? getUserOpHash(fromRpcUserOperation(sent), CHAIN_ID);
          return sentHash;
        }
        case 'eth_getUserOperationReceipt':
          if (receiptSuccess === null) {
            return null;
          }
          return {
            userOpHash: overrideReceiptHash ?? sentHash,
            success: receiptSuccess,
            actualGasUsed: '0x1',
            actualGasCost: '0x1',
            receipt: { transactionHash: TX_HASH },
          };
        default:
          throw new Error(`unexpected method: ${method}`);
      }
    },
  };
}
