/**
 * Wallet ファサードの emergencyRevokeValidator 配線検証。
 *
 * createWallet 経由（実 storage / 実鍵、fake `EvmCallSource` / `BundlerRpc` 注入）で以下を検証する:
 * - K1 派生鍵（`deriveKey` の keyId）の署名で UserOperation を構築・送信し、結果を返す。
 * - 成功時に Dashboard ログへ `emergencyRevoked` エントリ（`reason` / `txHash` 付き）を追記する。
 * - 署名に使う Validator が install されていない場合は 1022。
 * - Dashboard ログ追記の失敗（アクティブペルソナ未設定）は失効自体を失敗させず、`console.error` では
 *   なく注入した構造化ロガーへ `component: 'sdk.aa'` 付きで記録する。
 */

import { describe, expect, it } from 'bun:test';
import { Interface } from 'ethers';
import type { BundlerRpc } from '../../../internal/aa/bundler.js';
import {
  ENTRY_POINT_V07_ADDRESS,
  type Hex,
  type UserOperationV07,
} from '../../../internal/aa/types.js';
import { getUserOpHash } from '../../../internal/aa/user-operation.js';
import type { EvmCallRequest, EvmCallSource } from '../../../internal/asset/rpc.js';
import { type ErrorCode, VericertsError } from '../../../internal/errors.js';
import { ethereumPath } from '../../../internal/keymanager/hd.js';
import { MemoryStorage } from '../../../storage/storage.js';
import type { EmergencyRevokeOptions } from '../../aa-api.js';
import { createWallet } from '../../factory.js';
import type { Logger } from '../../options.js';
import type { Wallet } from '../../types.js';
import { findLog, recordingLogger } from '../metrics/logger.fixtures.js';

const TEST_MNEMONIC =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const ACCOUNT = '0x100000000000000000000000000000000000000a';
const OTHER_VALIDATOR = '0x300000000000000000000000000000000000000c';
const TX_HASH = `0x${'aa'.repeat(32)}` as `0x${string}`;
const USER_OP_HASH = `0x${'bb'.repeat(32)}` as `0x${string}`;
const CHAIN_ID = 1;

const MODULAR_ACCOUNT_IFACE = new Interface([
  'function getValidators() view returns (address[])',
  'function validatorWeight(address validator) view returns (uint256)',
  'function threshold() view returns (uint256)',
]);
const ENTRY_POINT_IFACE = new Interface([
  'function getNonce(address sender, uint192 key) view returns (uint256)',
]);

/** 最初の読み出しは `validators`、以降（失効後の読み直し）は署名 Validator だけが残った状態を返す。 */
function fakeCallSource(validators: readonly string[], signingValidator: string): EvmCallSource {
  let validatorReads = 0;
  return {
    async call(request: EvmCallRequest): Promise<string> {
      if (request.to === ACCOUNT) {
        const parsed = MODULAR_ACCOUNT_IFACE.parseTransaction({ data: request.data });
        if (parsed?.name === 'getValidators') {
          const installed = validatorReads++ === 0 ? validators : [signingValidator];
          return MODULAR_ACCOUNT_IFACE.encodeFunctionResult('getValidators', [installed]);
        }
        if (parsed?.name === 'validatorWeight') {
          return MODULAR_ACCOUNT_IFACE.encodeFunctionResult('validatorWeight', [1n]);
        }
        if (parsed?.name === 'threshold') {
          return MODULAR_ACCOUNT_IFACE.encodeFunctionResult('threshold', [1n]);
        }
        throw new Error(`unexpected function call: ${parsed?.name}`);
      }
      if (request.to === ENTRY_POINT_V07_ADDRESS) {
        return ENTRY_POINT_IFACE.encodeFunctionResult('getNonce', [1n]);
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

/** hexlify 済み UserOperation を戻す（実 Bundler と同じく、送られたものの実ハッシュを返すため）。 */
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

function fakeBundlerRpc(): BundlerRpc {
  let sentHash: string = USER_OP_HASH;
  return {
    async request(method: string, params: readonly unknown[]): Promise<unknown> {
      switch (method) {
        case 'eth_estimateUserOperationGas':
          return { preVerificationGas: '0x1', verificationGasLimit: '0x2', callGasLimit: '0x3' };
        case 'eth_sendUserOperation':
          // 実装が計算した userOpHash と照合されるため、固定値ではなく実ハッシュを返す。
          sentHash = getUserOpHash(
            fromRpcUserOperation(params[0] as Record<string, unknown>),
            CHAIN_ID,
          );
          return sentHash;
        case 'eth_getUserOperationReceipt':
          return {
            userOpHash: sentHash,
            success: true,
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

/** 呼ばれたら失敗する view シーム（必須項目の検証が送信前に走ることを示すため）。 */
function failingCallSource(): EvmCallSource {
  return {
    async call(): Promise<string> {
      throw new Error('must not reach the chain when required options are missing');
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

/** 呼ばれたら失敗する Bundler シーム。 */
function failingBundlerRpc(): BundlerRpc {
  return {
    async request(): Promise<unknown> {
      throw new Error('must not reach the bundler when required options are missing');
    },
  };
}

async function setup(): Promise<{ wallet: Wallet; keyId: string }> {
  const storage = new MemoryStorage();
  const wallet = await createWallet({ storage });
  await wallet.importMnemonic(TEST_MNEMONIC);
  const persona = await wallet.createPersona();
  await wallet.setActivePersona(persona.id);
  const keyPair = await wallet.deriveKey(ethereumPath(0, 0));
  return { wallet, keyId: keyPair.id };
}

/**
 * アクティブペルソナを一切設定しない Wallet を用意する（盗難直後・復旧直後の現実的な状況、
 * `facade.ts` の `appendRevokeLog` docblock参照）。Dashboard ログ署名鍵の解決
 * （`resolveActiveSigner`）が `PERSONA_NOT_FOUND`（2005）で失敗する経路を作る。
 */
async function setupWithoutActivePersona(
  logger: Logger,
): Promise<{ wallet: Wallet; keyId: string }> {
  const storage = new MemoryStorage();
  const wallet = await createWallet({ storage, logger });
  await wallet.importMnemonic(TEST_MNEMONIC);
  const keyPair = await wallet.deriveKey(ethereumPath(0, 0));
  return { wallet, keyId: keyPair.id };
}

function baseOpts(
  keyId: string,
  signingValidatorAddress: string,
  validators: readonly string[],
): EmergencyRevokeOptions {
  return {
    keyId,
    accountAddress: ACCOUNT,
    signingValidatorAddress,
    chainId: CHAIN_ID,
    callSource: fakeCallSource(validators, signingValidatorAddress),
    bundlerRpc: fakeBundlerRpc(),
    maxFeePerGas: 1_000_000_000n,
    maxPriorityFeePerGas: 900_000_000n,
    maxReceiptAttempts: 1,
    receiptPollIntervalMs: 0,
  };
}

describe('Wallet.emergencyRevokeValidator', () => {
  it('署名者以外の Validator を revokedValidators として返し、Dashboard ログに記録する', async () => {
    const { wallet, keyId } = await setup();
    const signingValidator = `0x${'2'.padStart(40, '0')}`;

    const result = await wallet.emergencyRevokeValidator(
      'stolen',
      baseOpts(keyId, signingValidator, [signingValidator, OTHER_VALIDATOR]),
    );

    expect(result.txHash).toBe(TX_HASH);
    expect(result.revokedValidators.map((v) => v.toLowerCase())).toEqual([
      OTHER_VALIDATOR.toLowerCase(),
    ]);
    expect(result.newWuaRequired).toBe(true);

    const blob = await wallet.exportDashboardLog({ types: ['emergencyRevoked'] });
    const lines = (await blob.text())
      .split('\n')
      .map((l) => JSON.parse(l) as Record<string, unknown>);
    const entry = lines.find((l) => l.type === 'emergencyRevoked');
    expect(entry).toBeDefined();
    const payload = entry?.payload as Record<string, unknown>;
    expect(payload.reason).toBe('stolen');
    expect(payload.txHash).toBe(TX_HASH);
  });

  it('署名に使う Validator が install されていない場合は 1022', async () => {
    const { wallet, keyId } = await setup();
    const signingValidator = `0x${'2'.padStart(40, '0')}`;

    try {
      await wallet.emergencyRevokeValidator(
        'lost',
        baseOpts(keyId, signingValidator, [OTHER_VALIDATOR]),
      );
      throw new Error('expected rejection');
    } catch (error) {
      expect(error).toBeInstanceOf(VericertsError);
      expect((error as VericertsError).code).toBe('1022');
    }

    // Validator 不存在で失敗した場合は Dashboard ログに記録しない。
    const blob = await wallet.exportDashboardLog({ types: ['emergencyRevoked'] });
    const lines = (await blob.text()).split('\n').filter((l) => l.length > 0);
    const entries = lines
      .map((l) => JSON.parse(l) as Record<string, unknown>)
      .filter((l) => l.type === 'emergencyRevoked');
    expect(entries).toHaveLength(0);
  });

  it('必須項目が欠けていたら、チェーンに一切触れずに落とす', async () => {
    // `?? ''` / `?? 0` / `?? 0n` で既定値を埋めると、chainId=0 のまま UserOpHash のドメイン分離へ
    // 入る（別チェーン向けに解釈され得る UserOperation を署名する）、fee 0 の UserOperation を
    // 送る、といった形で「呼び出し側が明示していない値」でチェーンに触れてしまう。
    // JS 呼び出し元・Object.prototype 汚染下では型は守ってくれないので実行時に弾く。
    const { wallet, keyId } = await setup();
    const base: EmergencyRevokeOptions = {
      keyId,
      accountAddress: ACCOUNT,
      signingValidatorAddress: `0x${'2'.padStart(40, '0')}`,
      chainId: CHAIN_ID,
      callSource: failingCallSource(),
      bundlerRpc: failingBundlerRpc(),
      maxFeePerGas: 1_000_000_000n,
      maxPriorityFeePerGas: 900_000_000n,
    };

    const cases: ReadonlyArray<readonly [Partial<Record<string, unknown>>, ErrorCode]> = [
      [{ keyId: '' }, '1022'],
      [{ accountAddress: undefined }, '1022'],
      [{ signingValidatorAddress: undefined }, '1022'],
      [{ chainId: 0 }, '1021'],
      [{ chainId: undefined }, '1021'],
      [{ maxFeePerGas: 0n }, '1021'],
      [{ maxPriorityFeePerGas: undefined }, '1021'],
      // 予算は任意だが、指定されたなら不正値を無視して署名させない。
      [{ maxTotalCostWei: 0n }, '1021'],
      [{ maxTotalCostWei: 1 }, '1021'],
    ];

    for (const [patch, code] of cases) {
      const opts = { ...base, ...patch } as EmergencyRevokeOptions;
      try {
        await wallet.emergencyRevokeValidator('stolen', opts);
        throw new Error(`expected rejection for ${JSON.stringify(Object.keys(patch))}`);
      } catch (error) {
        expect(error).toBeInstanceOf(VericertsError);
        expect((error as VericertsError).code).toBe(code);
      }
    }
  });

  it('Dashboard ログ追記の失敗（アクティブペルソナ未設定）は失効自体を失敗させず、logger.error(component: sdk.aa) で記録する', async () => {
    const { logger, logs } = recordingLogger();
    const { wallet, keyId } = await setupWithoutActivePersona(logger);
    const signingValidator = `0x${'2'.padStart(40, '0')}`;

    const result = await wallet.emergencyRevokeValidator(
      'stolen',
      baseOpts(keyId, signingValidator, [signingValidator, OTHER_VALIDATOR]),
    );

    // Dashboard ログ追記が失敗しても、チェーン上で確定済みの失効結果はそのまま返す。
    expect(result.txHash).toBe(TX_HASH);

    const attrs = findLog(logs, 'error', 'failed to append emergencyRevoked dashboard log')?.attrs;
    expect(attrs).toBeDefined();
    expect(attrs?.component).toBe('sdk.aa');
    expect(attrs?.error_code).toBe('2005');
  });
});
