import { describe, expect, test } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import type { AbiCodec } from '../../codec.js';
import {
  type Erc20ReadDeps,
  getTokenBalance,
  getTokenDecimals,
  getTokenSymbol,
  NATIVE_TOKEN_ADDRESS,
} from '../../erc20.js';
import type { EvmCallRequest, EvmCallSource } from '../../rpc.js';

const HOLDER = '0x1111111111111111111111111111111111111111';
const TOKEN = '0x2222222222222222222222222222222222222222';
const CHAIN_ID = 1;

/** 呼び出しを記録する fake codec。decode は関数名ごとに固定値を返す。 */
function fakeCodec(decoded: Record<string, readonly unknown[]>): AbiCodec & {
  encodeCalls: { fn: string; args: readonly unknown[] }[];
} {
  const encodeCalls: { fn: string; args: readonly unknown[] }[] = [];
  return {
    encodeCalls,
    encode(fn, args) {
      encodeCalls.push({ fn, args });
      return `0xdata_${fn}`;
    },
    decode(fn, _data) {
      const value = decoded[fn];
      if (value === undefined) {
        throw new Error(`unexpected decode: ${fn}`);
      }
      return value;
    },
  };
}

/** eth_call / nativeBalance を記録する fake call source。 */
function fakeCallSource(overrides?: Partial<EvmCallSource>): EvmCallSource & {
  callRequests: EvmCallRequest[];
  nativeCalls: { chainId: number; address: string }[];
} {
  const callRequests: EvmCallRequest[] = [];
  const nativeCalls: { chainId: number; address: string }[] = [];
  return {
    callRequests,
    nativeCalls,
    async call(request) {
      callRequests.push(request);
      return '0xraw';
    },
    async nativeBalance(chainId, address) {
      nativeCalls.push({ chainId, address });
      return 777n;
    },
    // read テストでは送金経路の fetchTxParams / send は使わない。
    async fetchTxParams() {
      throw new Error('not used');
    },
    async send() {
      throw new Error('not used');
    },
    ...overrides,
  };
}

function deps(codec: AbiCodec, callSource: EvmCallSource): Erc20ReadDeps {
  return { codec, callSource };
}

describe('getTokenBalance', () => {
  test('ERC-20 balanceOf を eth_call で読み取り bigint を返す', async () => {
    const codec = fakeCodec({ balanceOf: [123456789012345678901234567890n] });
    const callSource = fakeCallSource();
    const balance = await getTokenBalance(CHAIN_ID, HOLDER, TOKEN, deps(codec, callSource));
    expect(balance).toBe(123456789012345678901234567890n);
    // calldata は holder を引数に balanceOf でエンコードされる。
    expect(codec.encodeCalls).toEqual([{ fn: 'balanceOf', args: [HOLDER] }]);
    // eth_call は chainId / token / calldata で行われる。
    expect(callSource.callRequests).toEqual([
      { chainId: CHAIN_ID, to: TOKEN, data: '0xdata_balanceOf' },
    ]);
    expect(callSource.nativeCalls).toHaveLength(0);
  });

  test('uint256 戻り値が number / 文字列でも bigint に正規化する', async () => {
    const codec = fakeCodec({ balanceOf: ['42'] });
    const balance = await getTokenBalance(CHAIN_ID, HOLDER, TOKEN, deps(codec, fakeCallSource()));
    expect(balance).toBe(42n);
  });

  test('tokenAddress が "0x0" のとき ETH ネイティブ残高を取得する', async () => {
    const codec = fakeCodec({});
    const callSource = fakeCallSource();
    const balance = await getTokenBalance(
      CHAIN_ID,
      HOLDER,
      NATIVE_TOKEN_ADDRESS,
      deps(codec, callSource),
    );
    expect(balance).toBe(777n);
    expect(callSource.nativeCalls).toEqual([{ chainId: CHAIN_ID, address: HOLDER }]);
    // ネイティブ残高では eth_call / ABI encode を行わない。
    expect(callSource.callRequests).toHaveLength(0);
    expect(codec.encodeCalls).toHaveLength(0);
  });

  test('マルチチェーン: chainId は eth_call にそのまま伝播する', async () => {
    const codec = fakeCodec({ balanceOf: [1n] });
    for (const chainId of [1, 42161, 1868]) {
      const callSource = fakeCallSource();
      await getTokenBalance(chainId, HOLDER, TOKEN, deps(codec, callSource));
      expect(callSource.callRequests[0]?.chainId).toBe(chainId);
    }
  });

  test('holder アドレス不正で 4070 を投げ、RPC 呼び出しを行わない', async () => {
    const codec = fakeCodec({});
    const callSource = fakeCallSource();
    await expect(
      getTokenBalance(CHAIN_ID, '0xnotanaddress', TOKEN, deps(codec, callSource)),
    ).rejects.toMatchObject({ code: ErrorCodes.INVALID_EVM_ADDRESS });
    expect(callSource.callRequests).toHaveLength(0);
    expect(callSource.nativeCalls).toHaveLength(0);
  });

  test('token アドレス不正で 4070 を投げる（holder は妥当）', async () => {
    const codec = fakeCodec({});
    await expect(
      getTokenBalance(CHAIN_ID, HOLDER, '0x123', deps(codec, fakeCallSource())),
    ).rejects.toMatchObject({ code: ErrorCodes.INVALID_EVM_ADDRESS });
  });

  test('RPC 失敗（callSource）の VericertsError をそのまま伝播する', async () => {
    const codec = fakeCodec({ balanceOf: [1n] });
    const callSource = fakeCallSource({
      async call() {
        throw new VericertsError(ErrorCodes.CHAIN_SUBMIT_FAILED);
      },
    });
    await expect(
      getTokenBalance(CHAIN_ID, HOLDER, TOKEN, deps(codec, callSource)),
    ).rejects.toMatchObject({ code: ErrorCodes.CHAIN_SUBMIT_FAILED });
  });

  test('未設定チェーン（4071）を callSource からそのまま伝播する', async () => {
    const codec = fakeCodec({ balanceOf: [1n] });
    const callSource = fakeCallSource({
      async call() {
        throw new VericertsError(ErrorCodes.CHAIN_NOT_CONFIGURED);
      },
    });
    await expect(
      getTokenBalance(999, HOLDER, TOKEN, deps(codec, callSource)),
    ).rejects.toMatchObject({ code: ErrorCodes.CHAIN_NOT_CONFIGURED });
  });

  test('戻り値が空配列のとき 1021（デコード失敗）に正規化する', async () => {
    const codec = fakeCodec({ balanceOf: [] });
    await expect(
      getTokenBalance(CHAIN_ID, HOLDER, TOKEN, deps(codec, fakeCallSource())),
    ).rejects.toMatchObject({ code: ErrorCodes.CHAIN_SUBMIT_FAILED });
  });
});

describe('getTokenDecimals', () => {
  test('decimals() を読み取り number を返す', async () => {
    const codec = fakeCodec({ decimals: [18] });
    const callSource = fakeCallSource();
    const decimals = await getTokenDecimals(CHAIN_ID, TOKEN, deps(codec, callSource));
    expect(decimals).toBe(18);
    expect(codec.encodeCalls).toEqual([{ fn: 'decimals', args: [] }]);
    expect(callSource.callRequests[0]?.to).toBe(TOKEN);
  });

  test('bigint 戻り値（uint8）も number に正規化する', async () => {
    const codec = fakeCodec({ decimals: [6n] });
    const decimals = await getTokenDecimals(CHAIN_ID, TOKEN, deps(codec, fakeCallSource()));
    expect(decimals).toBe(6);
  });

  test('アドレス不正で 4070 を投げる', async () => {
    const codec = fakeCodec({});
    await expect(
      getTokenDecimals(CHAIN_ID, 'bad', deps(codec, fakeCallSource())),
    ).rejects.toMatchObject({ code: ErrorCodes.INVALID_EVM_ADDRESS });
  });

  test('戻り値が空のとき 1021 に正規化する', async () => {
    const codec = fakeCodec({ decimals: [] });
    await expect(
      getTokenDecimals(CHAIN_ID, TOKEN, deps(codec, fakeCallSource())),
    ).rejects.toMatchObject({ code: ErrorCodes.CHAIN_SUBMIT_FAILED });
  });
});

describe('getTokenSymbol', () => {
  test('symbol() を読み取り文字列を返す', async () => {
    const codec = fakeCodec({ symbol: ['USDC'] });
    const symbol = await getTokenSymbol(CHAIN_ID, TOKEN, deps(codec, fakeCallSource()));
    expect(symbol).toBe('USDC');
    expect(codec.encodeCalls).toEqual([{ fn: 'symbol', args: [] }]);
  });

  test('アドレス不正で 4070 を投げる', async () => {
    const codec = fakeCodec({});
    await expect(
      getTokenSymbol(CHAIN_ID, '0x00', deps(codec, fakeCallSource())),
    ).rejects.toMatchObject({ code: ErrorCodes.INVALID_EVM_ADDRESS });
  });
});
