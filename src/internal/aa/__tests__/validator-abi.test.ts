/**
 * ModularAccount / EntryPoint ABI エンコード/デコードのユニットテスト。実 RPC 非依存。
 */

import { describe, expect, test } from 'bun:test';
import { AbiCoder, Interface } from 'ethers';
import {
  createEntryPointAbiCodec,
  createModularAccountAbiCodec,
  encodeValidatorSignature,
} from '../validator-abi.js';

const VALIDATOR_A = '0x1111111111111111111111111111111111111111';
const VALIDATOR_B = '0x2222222222222222222222222222222222222222';
const ACCOUNT = '0x3333333333333333333333333333333333333333';

describe('createModularAccountAbiCodec', () => {
  test('getValidators のデコードが address[] を返す', () => {
    const codec = createModularAccountAbiCodec();
    const iface = new Interface(['function getValidators() view returns (address[])']);
    const data = iface.encodeFunctionResult('getValidators', [[VALIDATOR_A, VALIDATOR_B]]);
    const [validators] = codec.decode('getValidators', data) as [string[]];
    expect(validators.map((v) => v.toLowerCase())).toEqual([
      VALIDATOR_A.toLowerCase(),
      VALIDATOR_B.toLowerCase(),
    ]);
  });

  test('uninstallValidator が (address, bytes) を calldata にエンコードする', () => {
    const codec = createModularAccountAbiCodec();
    const data = codec.encode('uninstallValidator', [VALIDATOR_A, '0x']);
    const iface = new Interface(['function uninstallValidator(address validator, bytes data)']);
    const decoded = iface.decodeFunctionData('uninstallValidator', data);
    expect(decoded[0].toLowerCase()).toBe(VALIDATOR_A.toLowerCase());
    expect(decoded[1]).toBe('0x');
  });

  test('executeBatch が (address[], uint256[], bytes[]) を calldata にエンコードする', () => {
    const codec = createModularAccountAbiCodec();
    const innerCall = codec.encode('uninstallValidator', [VALIDATOR_A, '0x']);
    const data = codec.encode('executeBatch', [[ACCOUNT], [0n], [innerCall]]);
    const iface = new Interface([
      'function executeBatch(address[] dest, uint256[] value, bytes[] func) returns (bytes[])',
    ]);
    const decoded = iface.decodeFunctionData('executeBatch', data);
    expect(decoded[0][0].toLowerCase()).toBe(ACCOUNT.toLowerCase());
    expect(decoded[1][0]).toBe(0n);
    expect(decoded[2][0]).toBe(innerCall);
  });
});

describe('createEntryPointAbiCodec', () => {
  test('getNonce のデコードが uint256 を返す', () => {
    const codec = createEntryPointAbiCodec();
    const iface = new Interface([
      'function getNonce(address sender, uint192 key) view returns (uint256)',
    ]);
    const data = iface.encodeFunctionResult('getNonce', [42n]);
    const [nonce] = codec.decode('getNonce', data) as [bigint];
    expect(nonce).toBe(42n);
  });
});

describe('encodeValidatorSignature', () => {
  test('abi.encode(address, bytes) を返し、bytes は r||s||v(27/28) の 65 バイト', () => {
    const signature = new Uint8Array(65);
    signature.fill(0xaa, 0, 32); // r
    signature.fill(0xbb, 32, 64); // s
    signature[64] = 0; // 元の recovery バイト（encodeValidatorSignature は再構成するため無視される）

    const encoded = encodeValidatorSignature(VALIDATOR_A, signature, 1);

    const [decodedValidator, innerSig] = AbiCoder.defaultAbiCoder().decode(
      ['address', 'bytes'],
      encoded,
    ) as unknown as [string, string];
    expect(decodedValidator.toLowerCase()).toBe(VALIDATOR_A.toLowerCase());

    const innerBytes = Buffer.from(innerSig.slice(2), 'hex');
    expect(innerBytes.length).toBe(65);
    expect(innerBytes[64]).toBe(28); // recovery(1) + 27
    expect(innerBytes.subarray(0, 32).every((b) => b === 0xaa)).toBe(true);
    expect(innerBytes.subarray(32, 64).every((b) => b === 0xbb)).toBe(true);
  });

  test('recovery=0 のとき v=27', () => {
    const signature = new Uint8Array(65);
    const encoded = encodeValidatorSignature(VALIDATOR_A, signature, 0);
    const [, innerSig] = AbiCoder.defaultAbiCoder().decode(
      ['address', 'bytes'],
      encoded,
    ) as unknown as [string, string];
    const innerBytes = Buffer.from(innerSig.slice(2), 'hex');
    expect(innerBytes[64]).toBe(27);
  });
});
