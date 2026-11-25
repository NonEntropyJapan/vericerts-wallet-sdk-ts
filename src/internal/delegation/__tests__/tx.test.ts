import { describe, expect, test } from 'bun:test';
import { VericertsError } from '../../errors.js';
import { createErc1056AbiEncoder } from '../ethers-adapter.js';
import {
  type AbiEncoder,
  buildRemoveControllerTx,
  buildSetControllerTx,
  type ControllerTxDeps,
} from '../tx.js';

const REGISTRY = '0xdca7ef03e98e0dc2b855be647c39abe984fcf21b';
const IDENTITY = '0x1111111111111111111111111111111111111111';
const CONTROLLER = '0x2222222222222222222222222222222222222222';

/** 呼び出し引数を記録するモックエンコーダ。 */
function recordingEncoder(): {
  encoder: AbiEncoder;
  calls: Array<{ functionName: string; args: readonly unknown[] }>;
} {
  const calls: Array<{ functionName: string; args: readonly unknown[] }> = [];
  const encoder: AbiEncoder = {
    encodeFunctionData(functionName, args) {
      calls.push({ functionName, args });
      return '0xMOCKDATA';
    },
  };
  return { encoder, calls };
}

describe('buildSetControllerTx', () => {
  test('to=レジストリ・changeOwner(identity, newOwner) をエンコード', () => {
    const { encoder, calls } = recordingEncoder();
    const deps: ControllerTxDeps = { registryAddress: REGISTRY, encoder };
    const tx = buildSetControllerTx(`did:ethr:${IDENTITY}`, `did:ethr:${CONTROLLER}`, deps);

    expect(tx.to).toBe(REGISTRY);
    expect(tx.data).toBe('0xMOCKDATA');
    expect(tx.value).toBe(0n);
    expect(tx.chainId).toBe(1);
    expect(calls).toHaveLength(1);
    expect(calls[0]?.functionName).toBe('changeOwner');
    expect(calls[0]?.args).toEqual([IDENTITY, CONTROLLER]);
  });

  test('chainId は identity の DID から導出', () => {
    const { encoder } = recordingEncoder();
    const tx = buildSetControllerTx(`did:ethr:42161:${IDENTITY}`, `did:ethr:${CONTROLLER}`, {
      registryAddress: REGISTRY,
      encoder,
    });
    expect(tx.chainId).toBe(42161);
  });

  test('DID 形式不正は 2001', () => {
    const { encoder } = recordingEncoder();
    expect(() =>
      buildSetControllerTx('did:ethr:0xBAD', `did:ethr:${CONTROLLER}`, {
        registryAddress: REGISTRY,
        encoder,
      }),
    ).toThrow(VericertsError);
  });

  test('レジストリアドレス形式不正は 2001（remove と対称）', () => {
    const { encoder, calls } = recordingEncoder();
    try {
      buildSetControllerTx(`did:ethr:${IDENTITY}`, `did:ethr:${CONTROLLER}`, {
        registryAddress: '0xBAD',
        encoder,
      });
      throw new Error('should have thrown');
    } catch (e) {
      expect(e).toBeInstanceOf(VericertsError);
      expect((e as VericertsError).code).toBe('2001');
    }
    // レジストリ検証はエンコード前に行うため encodeFunctionData は呼ばれない。
    expect(calls).toHaveLength(0);
  });
});

describe('buildRemoveControllerTx', () => {
  test('changeOwner(identity, identity) で自己所有に戻す', () => {
    const { encoder, calls } = recordingEncoder();
    const tx = buildRemoveControllerTx(`did:ethr:${IDENTITY}`, {
      registryAddress: REGISTRY,
      encoder,
    });
    expect(tx.to).toBe(REGISTRY);
    expect(calls[0]?.functionName).toBe('changeOwner');
    expect(calls[0]?.args).toEqual([IDENTITY, IDENTITY]);
  });

  test('レジストリアドレス形式不正は 2001', () => {
    const { encoder } = recordingEncoder();
    expect(() =>
      buildRemoveControllerTx(`did:ethr:${IDENTITY}`, { registryAddress: '0xBAD', encoder }),
    ).toThrow(VericertsError);
  });
});

describe('createErc1056AbiEncoder（ethers 既定実装）', () => {
  test('changeOwner の selector + 引数を ABI エンコード', () => {
    const encoder = createErc1056AbiEncoder();
    const data = encoder.encodeFunctionData('changeOwner', [IDENTITY, CONTROLLER]);
    // changeOwner(address,address) の関数セレクタ（keccak256 先頭 4 バイト）。
    expect(data.startsWith('0xf00d4b5d')).toBe(true);
    // 32 バイト境界で右詰めされた 2 つのアドレスを含む。
    expect(data.toLowerCase()).toContain(IDENTITY.slice(2).toLowerCase());
    expect(data.toLowerCase()).toContain(CONTROLLER.slice(2).toLowerCase());
  });

  test('未署名 Tx の data に実エンコード結果が入る', () => {
    const encoder = createErc1056AbiEncoder();
    const tx = buildSetControllerTx(`did:ethr:${IDENTITY}`, `did:ethr:${CONTROLLER}`, {
      registryAddress: REGISTRY,
      encoder,
    });
    expect(tx.data.startsWith('0xf00d4b5d')).toBe(true);
  });

  test('不正引数は 2001 に正規化（cause にアドレスを漏らさない）', () => {
    const encoder = createErc1056AbiEncoder();
    try {
      encoder.encodeFunctionData('changeOwner', ['not-an-address', CONTROLLER]);
      throw new Error('should have thrown');
    } catch (e) {
      expect(e).toBeInstanceOf(VericertsError);
      expect((e as VericertsError).code).toBe('2001');
      expect((e as VericertsError).cause).toBeUndefined();
    }
  });
});
