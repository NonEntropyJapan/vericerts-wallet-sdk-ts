/**
 * `getValidators()` の応答件数上限。
 *
 * 侵害 RPC が巨大な `address[]` を返すと、ABI デコード → per-validator `uninstallValidator` 再エンコード →
 * `executeBatch` 再エンコードが件数に比例して同期的に走り、約 1 MB の応答で約 9 秒停止していた。
 * `MAX_INSTALLED_VALIDATORS`（ModularAccount の `_MAX_SIGNERS`）を超える応答は、デコード前に `1021` で拒否する。
 * 実時間ではなく「Bundler へ何も送られない / 失効後確認が成功扱いにならない」で決定的に pin する。
 */

import { describe, expect, test } from 'bun:test';
import type { EvmCallSource } from '../../../asset/rpc.js';
import type { RecoverableSignature } from '../../../keymanager/signer.js';
import { emergencyRevoke } from '../../emergency-revoke.js';
import { MAX_INSTALLED_VALIDATORS, readInstalledValidators } from '../../revoke-confirm.js';
import {
  ACCOUNT,
  CHAIN_ID,
  fakeBundlerRpc,
  fakeCallSource,
  MODULAR_ACCOUNT_IFACE,
  SIGNING_VALIDATOR,
} from './emergency-revoke.fixtures.js';

const fakeSign = async (): Promise<RecoverableSignature> => ({
  signature: new Uint8Array(65),
  recovery: 0,
});

const addr = (i: number): string => `0x${i.toString(16).padStart(40, '0')}`;
const others = (n: number): string[] => Array.from({ length: n }, (_, i) => addr(i + 1));

/** `getValidators` に任意の生 hex を返す callSource（他の関数は通常のフィクスチャへ委譲）。 */
function callSourceReturning(raw: string): EvmCallSource {
  const base = fakeCallSource([SIGNING_VALIDATOR]);
  return {
    ...base,
    async call(request) {
      if (request.to === ACCOUNT) {
        const parsed = MODULAR_ACCOUNT_IFACE.parseTransaction({ data: request.data });
        if (parsed?.name === 'getValidators') return raw;
      }
      return base.call(request);
    },
  };
}

function encodeValidators(validators: readonly string[]): string {
  return MODULAR_ACCOUNT_IFACE.encodeFunctionResult('getValidators', [validators]);
}

function run(callSource: EvmCallSource) {
  let sent = 0;
  const promise = emergencyRevoke({
    callSource,
    bundlerRpc: fakeBundlerRpc(true, () => {
      sent += 1;
    }),
    chainId: CHAIN_ID,
    accountAddress: ACCOUNT,
    signingValidatorAddress: SIGNING_VALIDATOR,
    sign: fakeSign,
    maxFeePerGas: 1_000_000_000n,
    maxPriorityFeePerGas: 900_000_000n,
  });
  return { promise, sent: () => sent };
}

const word = (n: bigint): string => n.toString(16).padStart(64, '0');

describe('emergencyRevoke — getValidators の件数上限', () => {
  // 件数 × 応答サイズの異なる形状。いずれも UserOperation を 1 件も送らず 1021。
  test.each([
    ['上限 + 1 件', encodeValidators([SIGNING_VALIDATOR, ...others(MAX_INSTALLED_VALIDATORS)])],
    ['3,000 件', encodeValidators([SIGNING_VALIDATOR, ...others(3_000)])],
    // 少数の実バイトで巨大な件数を主張する（デコーダに 2^255 件を確保させる形）。
    ['長さワードだけ巨大', `0x${word(0x20n)}${word(2n ** 255n)}`],
    ['長さ 17 で実体なし', `0x${word(0x20n)}${word(17n)}`],
    ['offset が 0x20 でない', `0x${word(0x40n)}${word(0n)}${word(0n)}`],
    ['正規エンコード + 末尾余剰', `${encodeValidators([SIGNING_VALIDATOR])}${'00'.repeat(32)}`],
    ['空応答 0x', '0x'],
  ])('%s は送信前に 1021 で拒否する', async (_label, raw) => {
    const { promise, sent } = run(callSourceReturning(raw));
    await expect(promise).rejects.toMatchObject({
      code: '1021',
      context: { phase: 'array_response_too_large' },
    });
    expect(sent()).toBe(0);
  });

  test('上限ちょうど（16 件）は受理され、署名 Validator 以外の 15 件が失効対象になる', async () => {
    const all = [SIGNING_VALIDATOR, ...others(MAX_INSTALLED_VALIDATORS - 1)];
    expect(all).toHaveLength(MAX_INSTALLED_VALIDATORS);
    const { promise, sent } = run(fakeCallSource(all));
    const result = await promise;
    expect(sent()).toBe(1);
    expect(result.revokedValidators).toHaveLength(MAX_INSTALLED_VALIDATORS - 1);
  });
});

describe('readInstalledValidators（失効後確認と共有）', () => {
  test('正常な一覧を返す', async () => {
    const list = [SIGNING_VALIDATOR, ...others(3)];
    const out = await readInstalledValidators(
      callSourceReturning(encodeValidators(list)),
      CHAIN_ID,
      ACCOUNT,
    );
    expect(out as string[]).toEqual(list);
  });

  test('空配列も受理する', async () => {
    await expect(
      readInstalledValidators(callSourceReturning(encodeValidators([])), CHAIN_ID, ACCOUNT),
    ).resolves.toEqual([]);
  });

  test.each([
    ['上限 + 1 件', encodeValidators(others(MAX_INSTALLED_VALIDATORS + 1))],
    ['3,000 件', encodeValidators(others(3_000))],
  ])('%s は 1021', async (_label, raw) => {
    await expect(
      readInstalledValidators(callSourceReturning(raw), CHAIN_ID, ACCOUNT),
    ).rejects.toMatchObject({ code: '1021' });
  });
});
