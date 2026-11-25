import { describe, expect, spyOn, test } from 'bun:test';
import { Contract, ContractTransactionResponse, Interface, JsonRpcProvider, Wallet } from 'ethers';
import { createChainClient, parseFromBlock } from './chain-client.mjs';

const RPC_URL = 'http://127.0.0.1:8545';
const REGISTRY_ADDRESS = `0x${'11'.repeat(20)}`;
// テスト専用のダミー鍵（anvil/hardhat の既知テストアカウント #0）。実チェーンには一切使わない。
const SIGNER_PRIVATE_KEY = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80';

const MODULUS_STATUS_IFACE = new Interface([
  'function modulusStatusForIss(bytes32,uint256[17]) view returns (bool registered, uint64 notAfter)',
]);
const KEY_OF_IFACE = new Interface([
  'function keyOf(bytes32) view returns (tuple(bytes32 issHash, bytes32 kidHash, uint64 notAfter, bool revoked, bool registered) key)',
]);

/** `runner.sendTransaction()` が返す想定の `TransactionResponseParams` 相当のダミー値。 */
function fakeTxResponseParams(hash) {
  return {
    hash,
    index: 0,
    type: 2,
    to: REGISTRY_ADDRESS,
    from: `0x${'22'.repeat(20)}`,
    nonce: 0,
    gasLimit: 100000n,
    data: '0x',
    value: 0n,
    gasPrice: 1n,
    maxPriorityFeePerGas: 1n,
    maxFeePerGas: 1n,
    maxFeePerBlobGas: null,
    chainId: 1n,
    signature: { r: `0x${'01'.repeat(32)}`, s: `0x${'02'.repeat(32)}`, v: 27 },
    accessList: [],
    blobVersionedHashes: null,
    authorizationList: null,
  };
}

describe('createChainClient', () => {
  test('signerPrivateKey 省略時は読み取り専用（canExecute === false）になる', () => {
    const chainClient = createChainClient({
      rpcUrl: 'http://127.0.0.1:8545',
      registryAddress: `0x${'11'.repeat(20)}`,
    });
    expect(chainClient.canExecute).toBe(false);
  });

  test('signerPrivateKey 設定時は実行可能（canExecute === true）になる', () => {
    // テスト専用のダミー鍵（anvil/hardhat の既知テストアカウント #0）。実チェーンには一切使わない。
    const chainClient = createChainClient({
      rpcUrl: 'http://127.0.0.1:8545',
      registryAddress: `0x${'11'.repeat(20)}`,
      signerPrivateKey: '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80',
    });
    expect(chainClient.canExecute).toBe(true);
  });

  test('署名者未設定で registerKey / setNotAfter を呼ぶと明示的に throw する（サイレント失敗を防ぐ）', async () => {
    const chainClient = createChainClient({
      rpcUrl: 'http://127.0.0.1:8545',
      registryAddress: `0x${'11'.repeat(20)}`,
    });
    await expect(
      chainClient.registerKey(
        `0x${'00'.repeat(32)}`,
        `0x${'00'.repeat(32)}`,
        Array(17).fill(0n),
        0n,
      ),
    ).rejects.toThrow(/signerPrivateKey/);
    await expect(chainClient.setNotAfter(`0x${'00'.repeat(32)}`, 0n)).rejects.toThrow(
      /signerPrivateKey/,
    );
  });

  test('destroy() は provider.destroy() を 1 回呼ぶ', async () => {
    const destroySpy = spyOn(JsonRpcProvider.prototype, 'destroy').mockImplementation(() => {});
    try {
      const chainClient = createChainClient({
        rpcUrl: 'http://127.0.0.1:8545',
        registryAddress: `0x${'11'.repeat(20)}`,
      });
      await chainClient.destroy();
      expect(destroySpy).toHaveBeenCalledTimes(1);
    } finally {
      destroySpy.mockRestore();
    }
  });
});

describe('createChainClient 読み取り系', () => {
  test('getModulusStatus は modulusStatusForIss の戻り値を { registered, notAfter } に整形する', async () => {
    const encoded = MODULUS_STATUS_IFACE.encodeFunctionResult('modulusStatusForIss', [true, 123n]);
    const callSpy = spyOn(JsonRpcProvider.prototype, 'call').mockImplementation(
      async () => encoded,
    );
    try {
      const chainClient = createChainClient({ rpcUrl: RPC_URL, registryAddress: REGISTRY_ADDRESS });
      const result = await chainClient.getModulusStatus(`0x${'00'.repeat(32)}`, Array(17).fill(0n));
      expect(result).toEqual({ registered: true, notAfter: 123n });
    } finally {
      callSpy.mockRestore();
    }
  });

  test('getKey は keyOf の戻り値をプレーンオブジェクトへ整形する', async () => {
    const issHash = `0x${'aa'.repeat(32)}`;
    const kidHash = `0x${'bb'.repeat(32)}`;
    const encoded = KEY_OF_IFACE.encodeFunctionResult('keyOf', [
      [issHash, kidHash, 999n, true, false],
    ]);
    const callSpy = spyOn(JsonRpcProvider.prototype, 'call').mockImplementation(
      async () => encoded,
    );
    try {
      const chainClient = createChainClient({ rpcUrl: RPC_URL, registryAddress: REGISTRY_ADDRESS });
      const result = await chainClient.getKey(`0x${'00'.repeat(32)}`);
      expect(result).toEqual({
        issHash,
        kidHash,
        notAfter: 999n,
        revoked: true,
        registered: false,
      });
    } finally {
      callSpy.mockRestore();
    }
  });

  test('getRegisteredEvents は複数の KeyRegistered ログを { keyId, kidHash, modulusHash } 配列へ整形する', async () => {
    const fakeLogs = [
      {
        args: {
          keyId: `0x${'11'.repeat(32)}`,
          kidHash: `0x${'22'.repeat(32)}`,
          modulusHash: `0x${'33'.repeat(32)}`,
        },
      },
      {
        args: {
          keyId: `0x${'44'.repeat(32)}`,
          kidHash: `0x${'55'.repeat(32)}`,
          modulusHash: `0x${'66'.repeat(32)}`,
        },
      },
    ];
    const queryFilterSpy = spyOn(Contract.prototype, 'queryFilter').mockImplementation(
      async () => fakeLogs,
    );
    try {
      const chainClient = createChainClient({ rpcUrl: RPC_URL, registryAddress: REGISTRY_ADDRESS });
      const events = await chainClient.getRegisteredEvents(`0x${'00'.repeat(32)}`);
      expect(events).toEqual([
        {
          keyId: fakeLogs[0].args.keyId,
          kidHash: fakeLogs[0].args.kidHash,
          modulusHash: fakeLogs[0].args.modulusHash,
        },
        {
          keyId: fakeLogs[1].args.keyId,
          kidHash: fakeLogs[1].args.kidHash,
          modulusHash: fakeLogs[1].args.modulusHash,
        },
      ]);
    } finally {
      queryFilterSpy.mockRestore();
    }
  });

  test('getRegisteredEvents はログが 0 件のとき空配列を返す', async () => {
    const queryFilterSpy = spyOn(Contract.prototype, 'queryFilter').mockImplementation(
      async () => [],
    );
    try {
      const chainClient = createChainClient({ rpcUrl: RPC_URL, registryAddress: REGISTRY_ADDRESS });
      const events = await chainClient.getRegisteredEvents(`0x${'00'.repeat(32)}`);
      expect(events).toEqual([]);
    } finally {
      queryFilterSpy.mockRestore();
    }
  });
});

describe('createChainClient 書き込み系（成功パス）', () => {
  test('registerKey 成功時は tx.wait() を 1 回待ってから tx hash を返す', async () => {
    const hash = `0x${'ab'.repeat(32)}`;
    const sendSpy = spyOn(Wallet.prototype, 'sendTransaction').mockImplementation(async () =>
      fakeTxResponseParams(hash),
    );
    const waitSpy = spyOn(ContractTransactionResponse.prototype, 'wait').mockImplementation(
      async () => null,
    );
    try {
      const chainClient = createChainClient({
        rpcUrl: RPC_URL,
        registryAddress: REGISTRY_ADDRESS,
        signerPrivateKey: SIGNER_PRIVATE_KEY,
      });
      const result = await chainClient.registerKey(
        `0x${'00'.repeat(32)}`,
        `0x${'00'.repeat(32)}`,
        Array(17).fill(0n),
        0n,
      );
      expect(result).toBe(hash);
      expect(waitSpy).toHaveBeenCalledTimes(1);
    } finally {
      sendSpy.mockRestore();
      waitSpy.mockRestore();
    }
  });

  test('setNotAfter 成功時は tx.wait() を 1 回待ってから tx hash を返す', async () => {
    const hash = `0x${'cd'.repeat(32)}`;
    const sendSpy = spyOn(Wallet.prototype, 'sendTransaction').mockImplementation(async () =>
      fakeTxResponseParams(hash),
    );
    const waitSpy = spyOn(ContractTransactionResponse.prototype, 'wait').mockImplementation(
      async () => null,
    );
    try {
      const chainClient = createChainClient({
        rpcUrl: RPC_URL,
        registryAddress: REGISTRY_ADDRESS,
        signerPrivateKey: SIGNER_PRIVATE_KEY,
      });
      const result = await chainClient.setNotAfter(`0x${'00'.repeat(32)}`, 123n);
      expect(result).toBe(hash);
      expect(waitSpy).toHaveBeenCalledTimes(1);
    } finally {
      sendSpy.mockRestore();
      waitSpy.mockRestore();
    }
  });

  test('fromBlock に空文字・空白のみ（未設定 secret 相当）を渡すと 0 で queryFilter する', async () => {
    for (const fromBlock of ['', '   ', '\n']) {
      const queryFilterSpy = spyOn(Contract.prototype, 'queryFilter').mockImplementation(
        async () => [],
      );
      try {
        const chainClient = createChainClient({
          rpcUrl: RPC_URL,
          registryAddress: REGISTRY_ADDRESS,
          fromBlock,
        });
        await chainClient.getRegisteredEvents(`0x${'00'.repeat(32)}`);
        expect(queryFilterSpy.mock.calls[0][1]).toBe(0);
      } finally {
        queryFilterSpy.mockRestore();
      }
    }
  });

  test('fromBlock の不正値は明示的に throw する（fail-closed。invalid blockTag に落とさない）', () => {
    for (const fromBlock of ['abc', '-1', '1.5', '0x10', -1, 1.5, Number.NaN, 2 ** 53]) {
      expect(() =>
        createChainClient({ rpcUrl: RPC_URL, registryAddress: REGISTRY_ADDRESS, fromBlock }),
      ).toThrow(/JWK_REGISTRY_FROM_BLOCK|fromBlock/);
    }
  });
});

describe('parseFromBlock', () => {
  test('未設定・空・空白のみは 0、10 進文字列と非負整数はそのまま数値化する', () => {
    expect(parseFromBlock(undefined)).toBe(0);
    expect(parseFromBlock(null)).toBe(0);
    expect(parseFromBlock('')).toBe(0);
    expect(parseFromBlock('  ')).toBe(0);
    expect(parseFromBlock(' 123 ')).toBe(123);
    expect(parseFromBlock('0')).toBe(0);
    expect(parseFromBlock(456)).toBe(456);
  });
});
