import { describe, expect, test } from 'bun:test';
import { VericertsError } from '../../../errors.js';
import type { AbiCodec } from '../../codec.js';
import type { Erc1155ReadDeps } from '../../erc1155.js';
import {
  getErc1155Balance,
  getErc1155BalanceBatch,
  getErc1155Uri,
  MAX_BALANCE_OF_BATCH,
} from '../../erc1155.js';
import type { EvmCallRequest, EvmCallSource } from '../../rpc.js';

const CONTRACT = '0x2222222222222222222222222222222222222222';
const ACCOUNT = '0x1111111111111111111111111111111111111111';
const ACCOUNT2 = '0x3333333333333333333333333333333333333333';

/** `uint256[]` を 1 個返す eth_call 戻り値（offset=0x20 || length || 要素...）を組み立てる。 */
function uintArrayReturn(length: number): string {
  const word = (n: number) => n.toString(16).padStart(64, '0');
  return `0x${word(0x20)}${word(length)}${'0'.repeat(64 * length)}`;
}

/** call の引数を記録し、関数名→戻り値（固定）を返す fake な EvmCallSource。 */
function fakeCallSource(opts?: {
  callReturn?: string;
  onCall?: (req: EvmCallRequest) => void;
  callThrows?: unknown;
}): EvmCallSource {
  return {
    async call(req: EvmCallRequest): Promise<string> {
      opts?.onCall?.(req);
      if (opts?.callThrows !== undefined) {
        throw opts.callThrows;
      }
      return opts?.callReturn ?? '0x';
    },
    // ERC-1155 read は call のみを使用する。送金経路用の seam はテストでは未使用。
    async nativeBalance(): Promise<bigint> {
      throw new Error('not used');
    },
    async fetchTxParams(): Promise<never> {
      throw new Error('not used');
    },
    async send(): Promise<string> {
      throw new Error('not used');
    },
  };
}

/** 関数名→デコード結果を返す fake な AbiCodec（encode は引数も記録できる）。 */
function fakeCodec(
  decodeMap: Record<string, readonly unknown[]>,
  onEncode?: (fn: string, args: readonly unknown[]) => void,
): AbiCodec {
  return {
    encode(fn: string, args: readonly unknown[]): string {
      onEncode?.(fn, args);
      return `0xENC_${fn}`;
    },
    decode(fn: string): readonly unknown[] {
      const value = decodeMap[fn];
      if (value === undefined) {
        throw new VericertsError('1021');
      }
      return value;
    },
  };
}

describe('getErc1155Balance', () => {
  test('balanceOf(account,id) を eth_call し bigint を返す', async () => {
    let captured: EvmCallRequest | undefined;
    let encArgs: readonly unknown[] | undefined;
    const deps: Erc1155ReadDeps = {
      callSource: fakeCallSource({
        onCall: (req) => {
          captured = req;
        },
      }),
      codec: fakeCodec({ balanceOf: [5n] }, (_fn, args) => {
        encArgs = args;
      }),
    };
    expect(await getErc1155Balance(1, CONTRACT, ACCOUNT, 99n, deps)).toBe(5n);
    expect(captured?.to).toBe(CONTRACT);
    expect(captured?.data).toBe('0xENC_balanceOf');
    expect(encArgs).toEqual([ACCOUNT, 99n]);
  });

  test('contract アドレス不正は 4070', async () => {
    const deps: Erc1155ReadDeps = {
      callSource: fakeCallSource(),
      codec: fakeCodec({ balanceOf: [0n] }),
    };
    await expect(getErc1155Balance(1, '0xBAD', ACCOUNT, 1n, deps)).rejects.toMatchObject({
      code: '4070',
    });
  });

  test('account アドレス不正は 4070', async () => {
    const deps: Erc1155ReadDeps = {
      callSource: fakeCallSource(),
      codec: fakeCodec({ balanceOf: [0n] }),
    };
    await expect(getErc1155Balance(1, CONTRACT, '0xBAD', 1n, deps)).rejects.toMatchObject({
      code: '4070',
    });
  });

  test('decode が空配列を返すと 1021', async () => {
    const deps: Erc1155ReadDeps = {
      callSource: fakeCallSource(),
      codec: fakeCodec({ balanceOf: [] }),
    };
    await expect(getErc1155Balance(1, CONTRACT, ACCOUNT, 1n, deps)).rejects.toMatchObject({
      code: '1021',
    });
  });
});

describe('getErc1155BalanceBatch', () => {
  test('balanceOfBatch を eth_call し bigint[] を返す', async () => {
    let encArgs: readonly unknown[] | undefined;
    const deps: Erc1155ReadDeps = {
      callSource: fakeCallSource({ callReturn: uintArrayReturn(3) }),
      codec: fakeCodec({ balanceOfBatch: [[1n, 2n, 3n]] }, (_fn, args) => {
        encArgs = args;
      }),
    };
    const balances = await getErc1155BalanceBatch(
      1,
      CONTRACT,
      [ACCOUNT, ACCOUNT2, ACCOUNT],
      [10n, 20n, 30n],
      deps,
    );
    expect(balances).toEqual([1n, 2n, 3n]);
    expect(encArgs).toEqual([
      [ACCOUNT, ACCOUNT2, ACCOUNT],
      [10n, 20n, 30n],
    ]);
  });

  test('number/string の残高も bigint に正規化する', async () => {
    const deps: Erc1155ReadDeps = {
      callSource: fakeCallSource({ callReturn: uintArrayReturn(2) }),
      codec: fakeCodec({ balanceOfBatch: [[7, '42']] }),
    };
    expect(await getErc1155BalanceBatch(1, CONTRACT, [ACCOUNT, ACCOUNT2], [1n, 2n], deps)).toEqual([
      7n,
      42n,
    ]);
  });

  test('accounts と ids の長さ不一致は 4070', async () => {
    const deps: Erc1155ReadDeps = {
      callSource: fakeCallSource(),
      codec: fakeCodec({ balanceOfBatch: [[1n]] }),
    };
    await expect(
      getErc1155BalanceBatch(1, CONTRACT, [ACCOUNT, ACCOUNT2], [1n], deps),
    ).rejects.toMatchObject({ code: '4070' });
  });

  test('account の 1 つでも不正なら 4070', async () => {
    const deps: Erc1155ReadDeps = {
      callSource: fakeCallSource(),
      codec: fakeCodec({ balanceOfBatch: [[1n, 2n]] }),
    };
    await expect(
      getErc1155BalanceBatch(1, CONTRACT, [ACCOUNT, '0xBAD'], [1n, 2n], deps),
    ).rejects.toMatchObject({ code: '4070' });
  });

  test('戻り値が配列でないと 1021', async () => {
    const deps: Erc1155ReadDeps = {
      callSource: fakeCallSource({ callReturn: uintArrayReturn(1) }),
      codec: fakeCodec({ balanceOfBatch: [123n] }),
    };
    await expect(getErc1155BalanceBatch(1, CONTRACT, [ACCOUNT], [1n], deps)).rejects.toMatchObject({
      code: '1021',
    });
  });

  // 要求 1 件に対し悪意あるコントラクトが大量のワードを返しても、デコード前に拒否する。
  // 少数の巨大応答 / 1 件超過 / offset 偽装 / 末尾余剰の各形状で、codec.decode が呼ばれない（= 決定的カウンタ 0）ことを pin する。
  test.each([
    ['要求 1 件に 8,000 ワード', uintArrayReturn(8000)],
    ['要求 1 件に 2 ワード（件数超過）', uintArrayReturn(2)],
    ['長さ 1 だが末尾に余剰ワード', `${uintArrayReturn(1)}${'0'.repeat(64)}`],
    ['長さ 2^255 の長さワード', `0x${'0'.repeat(62)}20${'8'.padEnd(64, '0')}`],
    ['offset が 0x20 でない', `0x${'0'.repeat(62)}40${'0'.repeat(63)}1${'0'.repeat(64)}`],
  ])('%s はデコード前に 1021 で拒否する', async (_label, callReturn) => {
    let decodeCalls = 0;
    const codec: AbiCodec = {
      encode: () => '0xENC',
      decode: () => {
        decodeCalls += 1;
        return [[1n]];
      },
    };
    await expect(
      getErc1155BalanceBatch(1, CONTRACT, [ACCOUNT], [1n], {
        callSource: fakeCallSource({ callReturn }),
        codec,
      }),
    ).rejects.toMatchObject({ code: '1021' });
    expect(decodeCalls).toBe(0);
  });

  test('要求件数が MAX_BALANCE_OF_BATCH を超えると RPC 前に 4070', async () => {
    let calls = 0;
    const n = MAX_BALANCE_OF_BATCH + 1;
    await expect(
      getErc1155BalanceBatch(1, CONTRACT, Array(n).fill(ACCOUNT), Array(n).fill(1n), {
        callSource: fakeCallSource({ onCall: () => (calls += 1) }),
        codec: fakeCodec({}),
      }),
    ).rejects.toMatchObject({ code: '4070' });
    expect(calls).toBe(0);
  });

  test('要求件数ちょうど MAX_BALANCE_OF_BATCH は受理する', async () => {
    const n = MAX_BALANCE_OF_BATCH;
    const balances = await getErc1155BalanceBatch(
      1,
      CONTRACT,
      Array(n).fill(ACCOUNT),
      Array(n).fill(1n),
      {
        callSource: fakeCallSource({ callReturn: uintArrayReturn(n) }),
        codec: fakeCodec({ balanceOfBatch: [Array(n).fill(0n)] }),
      },
    );
    expect(balances).toHaveLength(n);
  });
});

describe('getErc1155Uri', () => {
  test('uri(id) を eth_call し文字列を返す', async () => {
    const deps: Erc1155ReadDeps = {
      callSource: fakeCallSource(),
      codec: fakeCodec({ uri: ['ipfs://Qm.../{id}.json'] }),
    };
    expect(await getErc1155Uri(1, CONTRACT, 1n, deps)).toBe('ipfs://Qm.../{id}.json');
  });

  test('contract アドレス不正は 4070', async () => {
    const deps: Erc1155ReadDeps = {
      callSource: fakeCallSource(),
      codec: fakeCodec({ uri: ['x'] }),
    };
    await expect(getErc1155Uri(1, '0xBAD', 1n, deps)).rejects.toMatchObject({ code: '4070' });
  });

  test('decode が空配列を返すと 1021', async () => {
    const deps: Erc1155ReadDeps = {
      callSource: fakeCallSource(),
      codec: fakeCodec({ uri: [] }),
    };
    await expect(getErc1155Uri(1, CONTRACT, 1n, deps)).rejects.toMatchObject({ code: '1021' });
  });
});
