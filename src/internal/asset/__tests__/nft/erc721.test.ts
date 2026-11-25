import { describe, expect, test } from 'bun:test';
import { VericertsError } from '../../../errors.js';
import type { AbiCodec } from '../../codec.js';
import type { Erc721ReadDeps } from '../../erc721.js';
import {
  getErc721Balance,
  getErc721Owner,
  getErc721TokenUri,
  ownsErc721Token,
} from '../../erc721.js';
import type { EvmCallRequest, EvmCallSource } from '../../rpc.js';

const CONTRACT = '0x2222222222222222222222222222222222222222';
const OWNER = '0x1111111111111111111111111111111111111111';
const OTHER = '0x3333333333333333333333333333333333333333';

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
    // ERC-721 read は call のみを使用する。送金経路用の seam はテストでは未使用。
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

/** 関数名→デコード結果を返す fake な AbiCodec（encode は固定 calldata を返す）。 */
function fakeCodec(decodeMap: Record<string, readonly unknown[]>): AbiCodec {
  return {
    encode(fn: string): string {
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

describe('getErc721Balance', () => {
  test('balanceOf を eth_call し uint256 を bigint で返す', async () => {
    let captured: EvmCallRequest | undefined;
    const deps: Erc721ReadDeps = {
      callSource: fakeCallSource({
        callReturn: '0xBAL',
        onCall: (req) => {
          captured = req;
        },
      }),
      codec: fakeCodec({ balanceOf: [3n] }),
    };
    expect(await getErc721Balance(1, CONTRACT, OWNER, deps)).toBe(3n);
    expect(captured?.chainId).toBe(1);
    expect(captured?.to).toBe(CONTRACT);
    expect(captured?.data).toBe('0xENC_balanceOf');
  });

  test('number/string の残高も bigint に正規化する', async () => {
    const deps: Erc721ReadDeps = {
      callSource: fakeCallSource(),
      codec: fakeCodec({ balanceOf: ['42'] }),
    };
    expect(await getErc721Balance(1, CONTRACT, OWNER, deps)).toBe(42n);
  });

  test('contract アドレス不正は 4070', async () => {
    const deps: Erc721ReadDeps = {
      callSource: fakeCallSource(),
      codec: fakeCodec({ balanceOf: [0n] }),
    };
    await expect(getErc721Balance(1, '0xBAD', OWNER, deps)).rejects.toMatchObject({ code: '4070' });
  });

  test('owner アドレス不正は 4070', async () => {
    const deps: Erc721ReadDeps = {
      callSource: fakeCallSource(),
      codec: fakeCodec({ balanceOf: [0n] }),
    };
    await expect(getErc721Balance(1, CONTRACT, '0xBAD', deps)).rejects.toMatchObject({
      code: '4070',
    });
  });

  test('decode が空配列を返すと 1021', async () => {
    const deps: Erc721ReadDeps = {
      callSource: fakeCallSource(),
      codec: fakeCodec({ balanceOf: [] }),
    };
    await expect(getErc721Balance(1, CONTRACT, OWNER, deps)).rejects.toMatchObject({
      code: '1021',
    });
  });
});

describe('getErc721Owner', () => {
  test('ownerOf を eth_call しアドレス文字列を返す', async () => {
    let captured: EvmCallRequest | undefined;
    const deps: Erc721ReadDeps = {
      callSource: fakeCallSource({
        onCall: (req) => {
          captured = req;
        },
      }),
      codec: fakeCodec({ ownerOf: [OWNER] }),
    };
    expect(await getErc721Owner(1, CONTRACT, 42n, deps)).toBe(OWNER);
    expect(captured?.to).toBe(CONTRACT);
    expect(captured?.data).toBe('0xENC_ownerOf');
  });

  test('contract アドレス不正は 4070', async () => {
    const deps: Erc721ReadDeps = {
      callSource: fakeCallSource(),
      codec: fakeCodec({ ownerOf: [OWNER] }),
    };
    await expect(getErc721Owner(1, '0xBAD', 42n, deps)).rejects.toMatchObject({ code: '4070' });
  });

  test('RPC 失敗（1021）はそのまま伝播', async () => {
    const deps: Erc721ReadDeps = {
      callSource: fakeCallSource({ callThrows: new VericertsError('1021') }),
      codec: fakeCodec({ ownerOf: [OWNER] }),
    };
    await expect(getErc721Owner(1, CONTRACT, 42n, deps)).rejects.toMatchObject({ code: '1021' });
  });
});

describe('getErc721TokenUri', () => {
  test('tokenURI を eth_call し文字列を返す', async () => {
    const deps: Erc721ReadDeps = {
      callSource: fakeCallSource(),
      codec: fakeCodec({ tokenURI: ['ipfs://Qm.../1'] }),
    };
    expect(await getErc721TokenUri(1, CONTRACT, 1n, deps)).toBe('ipfs://Qm.../1');
  });

  test('contract アドレス不正は 4070', async () => {
    const deps: Erc721ReadDeps = {
      callSource: fakeCallSource(),
      codec: fakeCodec({ tokenURI: ['x'] }),
    };
    await expect(getErc721TokenUri(1, '0xBAD', 1n, deps)).rejects.toMatchObject({ code: '4070' });
  });

  test('decode が空配列を返すと 1021', async () => {
    const deps: Erc721ReadDeps = {
      callSource: fakeCallSource(),
      codec: fakeCodec({ tokenURI: [] }),
    };
    await expect(getErc721TokenUri(1, CONTRACT, 1n, deps)).rejects.toMatchObject({ code: '1021' });
  });
});

describe('ownsErc721Token', () => {
  test('ownerOf が一致すれば true（大文字小文字非依存）', async () => {
    const deps: Erc721ReadDeps = {
      callSource: fakeCallSource(),
      codec: fakeCodec({ ownerOf: [OWNER.toUpperCase().replace('0X', '0x')] }),
    };
    expect(await ownsErc721Token(1, CONTRACT, 7n, OWNER, deps)).toBe(true);
  });

  test('別アドレスが所有者なら false', async () => {
    const deps: Erc721ReadDeps = {
      callSource: fakeCallSource(),
      codec: fakeCodec({ ownerOf: [OTHER] }),
    };
    expect(await ownsErc721Token(1, CONTRACT, 7n, OWNER, deps)).toBe(false);
  });

  test('未所有トークンの ownerOf revert（1021）は false に正規化', async () => {
    const deps: Erc721ReadDeps = {
      callSource: fakeCallSource({ callThrows: new VericertsError('1021') }),
      codec: fakeCodec({ ownerOf: [OWNER] }),
    };
    expect(await ownsErc721Token(1, CONTRACT, 7n, OWNER, deps)).toBe(false);
  });

  test('未設定チェーン（4071）は false にせず再送する', async () => {
    const deps: Erc721ReadDeps = {
      callSource: fakeCallSource({ callThrows: new VericertsError('4071') }),
      codec: fakeCodec({ ownerOf: [OWNER] }),
    };
    await expect(ownsErc721Token(9, CONTRACT, 7n, OWNER, deps)).rejects.toMatchObject({
      code: '4071',
    });
  });

  test('owner アドレス不正は 4070（call 前に検証）', async () => {
    const deps: Erc721ReadDeps = {
      callSource: fakeCallSource(),
      codec: fakeCodec({ ownerOf: [OWNER] }),
    };
    await expect(ownsErc721Token(1, CONTRACT, 7n, '0xBAD', deps)).rejects.toMatchObject({
      code: '4070',
    });
  });
});
