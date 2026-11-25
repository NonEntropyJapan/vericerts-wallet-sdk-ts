/**
 * `typedDataV4Payload` の同名フィールド重複拒否と値ノード予算。
 *
 * 同名フィールドを許すと `data[name]` が同じ子/配列を何度も読み、JSON サイズに対して `fan^depth`（入れ子 struct）や
 * `K × N`（配列を K 個の同名フィールドで再読込）回のエンコードが走る。2 KB の typed data で署名計算が 18 秒止まっていた。
 * 実時間ではなく「message を 1 回も読まずに拒否する」「値ノード数の上限で止まる」を、読み取り回数・keccak256 回数で pin する。
 */

import { describe, expect, setDefaultTimeout, spyOn, test } from 'bun:test';
import { HEAVY_INPUT_TIMEOUT_MS } from '../../../__tests__/heavy-input-timeout.js';
import { ErrorCodes } from '../../../errors.js';
import * as addressModule from '../../../keymanager/address.js';
import { typedDataV4Payload } from '../../eth-signing.js';
import { MAX_ENCODE_NODES, type TypedData } from '../../eth-typed-data-types.js';

setDefaultTimeout(HEAVY_INPUT_TIMEOUT_MS);

const DOMAIN = { name: 'a' };

/** 深さ `depth`・各階層 `fan` 個の同名フィールド `x` が下の階層を指す入れ子 struct（再現スクリプトと同形）。 */
function nested(depth: number, fan: number): TypedData {
  const types: Record<string, { name: string; type: string }[]> = {};
  for (let d = 0; d < depth; d++) {
    types[`T${d}`] = Array.from({ length: fan }, () => ({
      name: 'x',
      type: d === depth - 1 ? 'uint256' : `T${d + 1}`,
    }));
  }
  let message: Record<string, unknown> = { x: 1 };
  for (let d = depth - 2; d >= 0; d--) message = { x: message };
  return { types, primaryType: 'T0', domain: DOMAIN, message };
}

/** `message` の自身のプロパティ読み取り回数を数える Proxy で包む。 */
function counted<T extends object>(target: T, counter: { reads: number }): T {
  return new Proxy(target, {
    get(obj, key, receiver) {
      counter.reads += 1;
      return Reflect.get(obj, key, receiver);
    },
  });
}

function expectSignFailed(fn: () => unknown): void {
  try {
    fn();
  } catch (error) {
    expect((error as { code: string }).code).toBe(ErrorCodes.SIGN_FAILED);
    return;
  }
  throw new Error('expected SIGN_FAILED');
}

describe('typedDataV4Payload: 同名フィールドの重複を拒否する', () => {
  // 形状: 深い入れ子（fan^depth）/ 浅く広い / 配列の同名再読込。いずれも message を 1 回も読まずに拒否する。
  test.each([
    ['depth7 × fan10（18 秒の再現入力）', nested(7, 10)],
    ['depth6 × fan10', nested(6, 10)],
    ['depth2 × fan1000（浅く広い）', nested(2, 1000)],
    ['depth1 × fan2（最小の重複）', nested(1, 2)],
  ])('%s', (_label, typedData) => {
    const counter = { reads: 0 };
    const message = counted(typedData.message as object, counter) as Record<string, unknown>;
    const keccak = spyOn(addressModule, 'keccak256');
    try {
      expectSignFailed(() => typedDataV4Payload({ ...typedData, message }));
      expect(counter.reads).toBe(0);
      // domainSeparator の計算（EIP712Domain の typeHash + `name` 文字列 + hashStruct = 3 回）以降は何もハッシュされない。
      expect(keccak.mock.calls.length).toBe(3);
    } finally {
      keccak.mockRestore();
    }
  });

  test('uint256[] を同名フィールド K 個で再読込する形（K=500 × N=20,000）', () => {
    const fields = Array.from({ length: 500 }, () => ({ name: 'a', type: 'uint256[]' }));
    const counter = { reads: 0 };
    const message = counted({ a: Array.from({ length: 20_000 }, (_, i) => i) }, counter);
    expectSignFailed(() =>
      typedDataV4Payload({
        types: { M: fields },
        primaryType: 'M',
        domain: DOMAIN,
        message: message as Record<string, unknown>,
      }),
    );
    expect(counter.reads).toBe(0);
  });

  test('参照される子 struct の重複も、親の値を読む前に拒否する', () => {
    const counter = { reads: 0 };
    const message = counted({ child: { v: 1 } }, counter);
    expectSignFailed(() =>
      typedDataV4Payload({
        types: {
          Child: [
            { name: 'v', type: 'uint256' },
            { name: 'v', type: 'uint256' },
          ],
          Root: [{ name: 'child', type: 'Child' }],
        },
        primaryType: 'Root',
        domain: DOMAIN,
        message: message as Record<string, unknown>,
      }),
    );
    expect(counter.reads).toBe(0);
  });

  test('同名でも型違い（重複は名前のみで判定）は拒否する', () => {
    expectSignFailed(() =>
      typedDataV4Payload({
        types: {
          M: [
            { name: 'a', type: 'uint256' },
            { name: 'a', type: 'string' },
          ],
        },
        primaryType: 'M',
        domain: DOMAIN,
        message: { a: 1 },
      }),
    );
  });

  test('重複のない通常の Permit 風 typed data は署名対象を返す', () => {
    const payload = typedDataV4Payload({
      types: {
        Permit: [
          { name: 'owner', type: 'address' },
          { name: 'spender', type: 'address' },
          { name: 'value', type: 'uint256' },
          { name: 'nonce', type: 'uint256' },
          { name: 'deadline', type: 'uint256' },
        ],
      },
      primaryType: 'Permit',
      domain: {
        name: 'Token',
        version: '1',
        chainId: 1,
        verifyingContract: `0x${'11'.repeat(20)}`,
      },
      message: {
        owner: `0x${'22'.repeat(20)}`,
        spender: `0x${'33'.repeat(20)}`,
        value: 1,
        nonce: 0,
        deadline: 9_999_999_999,
      },
    });
    expect(payload.length).toBe(2 + 32 + 32);
    expect(payload[0]).toBe(0x19);
    expect(payload[1]).toBe(0x01);
  });
});

describe('typedDataV4Payload: 値ノード数の予算', () => {
  const ARRAY_LEN = MAX_ENCODE_NODES + 1;

  // 形状: 巨大な平坦配列 / 多次元配列 / 小さな struct の大量配列。いずれも総ノード数で決定的に拒否する。
  test.each([
    [
      '平坦な uint256[]',
      {
        types: { M: [{ name: 'a', type: 'uint256[]' }] },
        message: { a: new Array(ARRAY_LEN).fill(1) },
      },
    ],
    [
      '二次元 uint256[][]（外側 450 × 内側 450）',
      {
        types: { M: [{ name: 'a', type: 'uint256[][]' }] },
        message: { a: Array.from({ length: 450 }, () => new Array(450).fill(1)) },
      },
    ],
    [
      '2 フィールドの struct を 70,000 個',
      {
        types: {
          S: [
            { name: 'p', type: 'uint256' },
            { name: 'q', type: 'uint256' },
          ],
          M: [{ name: 'a', type: 'S[]' }],
        },
        message: { a: Array.from({ length: 70_000 }, () => ({ p: 1, q: 2 })) },
      },
    ],
  ])('%s は上限超過で SIGN_FAILED', (_label, shape) => {
    expectSignFailed(() =>
      typedDataV4Payload({ ...shape, primaryType: 'M', domain: DOMAIN } as TypedData),
    );
  });

  test('上限ちょうど（MAX_ENCODE_NODES 個の値ノード）は受理する', () => {
    // M.a の encodeFieldValue 1 回 + 配列要素 MAX_ENCODE_NODES - 1 個 = 総ノード数 MAX_ENCODE_NODES。
    const typedData: TypedData = {
      types: { M: [{ name: 'a', type: 'uint256[]' }] },
      primaryType: 'M',
      domain: DOMAIN,
      message: { a: new Array(MAX_ENCODE_NODES - 1).fill(1) },
    };
    expect(() => typedDataV4Payload(typedData)).not.toThrow();
    const over: TypedData = { ...typedData, message: { a: new Array(MAX_ENCODE_NODES).fill(1) } };
    expectSignFailed(() => typedDataV4Payload(over));
  });
});
