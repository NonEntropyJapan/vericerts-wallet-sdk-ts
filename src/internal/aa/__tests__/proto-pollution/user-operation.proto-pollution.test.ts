/**
 * `buildUserOperation` の `Object.prototype` 汚染耐性テスト。
 *
 * ここで組み立てた UserOperation はそのまま `getUserOpHash` でハッシュされ、Validator が
 * 署名する対象になる。任意フィールドをプロトタイプ鎖で読むと、それらを**省略した**正当な
 * 組み立てでも攻撃者の `callData`（＝実行される呼び出し）・ガス / 手数料・`signature` が
 * 署名対象へ入り、UserOpHash ごと差し替わる。
 */

import { describe, expect, it } from 'bun:test';
import { withPollutedPrototype } from '../../../__tests__/prototype-pollution.fixtures.js';
import type { Hex, UserOperationV07 } from '../../types.js';
import { buildUserOperation, getUserOpHash } from '../../user-operation.js';

const SENDER = '0x1111111111111111111111111111111111111111' as Hex;
const CALL_DATA = '0xdeadbeef' as Hex;
const ATTACKER_CALL_DATA = '0xbadc0ffee0' as Hex;
const ATTACKER_SIGNATURE = `0x${'ab'.repeat(65)}` as Hex;

describe('buildUserOperation の Object.prototype 汚染耐性', () => {
  it('継承したガス・手数料・signature は UserOperation に載らない', () => {
    const userOp = withPollutedPrototype(
      {
        callGasLimit: 999_999n,
        verificationGasLimit: 888_888n,
        preVerificationGas: 777_777n,
        maxFeePerGas: 666_666n,
        maxPriorityFeePerGas: 555_555n,
        signature: ATTACKER_SIGNATURE,
      },
      () => buildUserOperation({ sender: SENDER, nonce: 0n, callData: CALL_DATA }),
    );
    expect(userOp.callGasLimit).toBe(0n);
    expect(userOp.verificationGasLimit).toBe(0n);
    expect(userOp.preVerificationGas).toBe(0n);
    expect(userOp.maxFeePerGas).toBe(0n);
    expect(userOp.maxPriorityFeePerGas).toBe(0n);
    expect(userOp.signature).not.toBe(ATTACKER_SIGNATURE);
  });

  it('継承した factory / factoryData は採用せず、片側指定エラーも起こさない', () => {
    const userOp = withPollutedPrototype({ factory: SENDER, factoryData: ATTACKER_CALL_DATA }, () =>
      buildUserOperation({ sender: SENDER, nonce: 0n, callData: CALL_DATA }),
    );
    expect(userOp.factory).toBeUndefined();
    expect(userOp.factoryData).toBeUndefined();
  });

  it('継承した callData は署名対象ハッシュを変えない', () => {
    const clean = buildUserOperation({ sender: SENDER, nonce: 0n, callData: CALL_DATA });
    const polluted = withPollutedPrototype({ callData: ATTACKER_CALL_DATA }, () =>
      buildUserOperation({ sender: SENDER, nonce: 0n, callData: CALL_DATA }),
    );
    expect(polluted.callData).toBe(CALL_DATA);
    expect(getUserOpHash(polluted, 1)).toBe(getUserOpHash(clean, 1));
  });

  it('明示的に渡したフィールドは従来どおり反映される（正常系）', () => {
    const userOp = buildUserOperation({
      sender: SENDER,
      nonce: 7n,
      callData: CALL_DATA,
      callGasLimit: 21_000n,
      maxFeePerGas: 100n,
      signature: ATTACKER_SIGNATURE,
    });
    expect(userOp.callGasLimit).toBe(21_000n);
    expect(userOp.maxFeePerGas).toBe(100n);
    expect(userOp.signature).toBe(ATTACKER_SIGNATURE);
    expect(userOp.nonce).toBe(7n);
  });

  it('factory / factoryData の片側指定は従来どおり拒否される（正常系）', () => {
    expect(() =>
      buildUserOperation({ sender: SENDER, nonce: 0n, callData: CALL_DATA, factory: SENDER }),
    ).toThrow();
  });
});

/**
 * viem の `getUserOperationHash`（`toPackedUserOperation` / `getInitCode`）は任意フィールドを分割代入で
 * 読むため、それらを own に持たない UserOperation を渡すと汚染値が署名対象ハッシュへ入る。
 */
describe('getUserOpHash の Object.prototype 汚染耐性', () => {
  const PAYMASTER = '0x2222222222222222222222222222222222222222' as Hex;
  const ATTACKER = '0x3333333333333333333333333333333333333333' as Hex;
  const FACTORY_DATA = '0xfac70000' as Hex;
  // buildUserOperation の戻り値は factory / factoryData を own に（undefined で）持つため、
  // 任意フィールドを own に持たない op をリテラルで組み立てる。
  const baseOp: UserOperationV07 = {
    sender: SENDER,
    nonce: 0n,
    callData: CALL_DATA,
    callGasLimit: 0n,
    verificationGasLimit: 0n,
    preVerificationGas: 0n,
    maxFeePerGas: 0n,
    maxPriorityFeePerGas: 0n,
    signature: '0x',
  };
  const sponsoredOp = {
    ...baseOp,
    paymaster: PAYMASTER,
    paymasterData: '0x' as Hex,
    paymasterVerificationGasLimit: 10n,
    paymasterPostOpGasLimit: 20n,
  };

  it('paymaster を持たない op: 継承した paymaster 系フィールドはハッシュを変えない', () => {
    const polluted = withPollutedPrototype(
      {
        paymaster: ATTACKER,
        paymasterData: '0xbad0',
        paymasterVerificationGasLimit: 12_345n,
        paymasterPostOpGasLimit: 6_789n,
      },
      () => getUserOpHash(baseOp, 1),
    );
    expect(polluted).toBe(getUserOpHash(baseOp, 1));
  });

  it('factory を持たない op: 継承した factory / factoryData はハッシュを変えない', () => {
    const polluted = withPollutedPrototype(
      { factory: ATTACKER, factoryData: ATTACKER_CALL_DATA },
      () => getUserOpHash(baseOp, 1),
    );
    expect(polluted).toBe(getUserOpHash(baseOp, 1));
  });

  it('paymaster を持つ op: 継承した paymasterSignature はハッシュを変えない', () => {
    const polluted = withPollutedPrototype({ paymasterSignature: ATTACKER_SIGNATURE }, () =>
      getUserOpHash(sponsoredOp, 1),
    );
    expect(polluted).toBe(getUserOpHash(sponsoredOp, 1));
  });

  it('factory を持つ op: 継承した authorization はハッシュを変えない', () => {
    // viem の getInitCode は forHash かつ factory が 0x7702 のとき authorization.address を initCode に使う。
    const eip7702Op = { ...baseOp, factory: '0x7702' as Hex, factoryData: FACTORY_DATA };
    const polluted = withPollutedPrototype(
      { authorization: { address: ATTACKER, chainId: 1, nonce: 0 } },
      () => getUserOpHash(eip7702Op, 1),
    );
    expect(polluted).toBe(getUserOpHash(eip7702Op, 1));
  });

  it('自身に持つ paymaster 系フィールドは継承値より優先されてハッシュへ反映される（正常系）', () => {
    // 自身の値が継承値より優先されることの確認であり、修正前から通る（回帰の検出は上の 4 件が担う）。
    const clean = getUserOpHash(sponsoredOp, 1);
    const polluted = withPollutedPrototype(
      { paymaster: ATTACKER, paymasterVerificationGasLimit: 12_345n },
      () => getUserOpHash(sponsoredOp, 1),
    );
    expect(polluted).toBe(clean);
    expect(clean).not.toBe(getUserOpHash(baseOp, 1));
  });
});
