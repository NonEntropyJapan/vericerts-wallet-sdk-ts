/**
 * ERC-20 送金のガス上限検査。
 *
 * 侵害 RPC が `eth_gasPrice` / `eth_estimateGas` に極端な値を返しても、署名・ブロードキャストの前に
 * `1021`（`phase: gas_limit_exceeded | gas_cost_exceeded`）で拒否する。署名 / 送信が 1 回も呼ばれないことで pin する。
 */

import { describe, expect, test } from 'bun:test';
import type { Signer } from '../../../keymanager/keymanager.js';
import {
  buildTransferTx,
  signAndSendTransaction,
  type TransactionRequest,
  type TxSerializer,
} from '../../erc20-tx.js';
import {
  DEFAULT_MAX_TX_FEE_WEI,
  MAX_GAS_PRICE_WEI,
  MAX_TX_GAS_LIMIT,
} from '../../tx-fee-limits.js';
import { fakeCallSource, fakeCodec } from '../erc20/erc20-tx.fakes.js';

const TOKEN = '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48';
const TO = '0x70997970C51812dc3A010C7d01b50e0d17dc79C8';
const FROM = '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266';
const GWEI = 1_000_000_000n;

function build(params: { gasLimit: bigint; gasPrice: bigint }, maxTotalCostWei?: bigint) {
  const { codec } = fakeCodec();
  const { callSource } = fakeCallSource({ nonce: 1, ...params });
  return buildTransferTx(1, FROM, TO, 1n, TOKEN, { codec, callSource, maxTotalCostWei });
}

describe('buildTransferTx: RPC 由来ガス値の上限', () => {
  // 形状: gasPrice だけ巨大 / gasLimit だけ巨大 / 両方がそれぞれ上限内でも積が大きい / 負値。
  test.each([
    [
      'gasPrice 50,000 gwei（再現入力）',
      { gasLimit: 100_000n, gasPrice: 50_000n * GWEI },
      'gas_limit_exceeded',
    ],
    [
      'gasPrice 上限 + 1 wei',
      { gasLimit: 21_000n, gasPrice: MAX_GAS_PRICE_WEI + 1n },
      'gas_limit_exceeded',
    ],
    [
      'gasLimit 上限 + 1',
      { gasLimit: MAX_TX_GAS_LIMIT + 1n, gasPrice: GWEI },
      'gas_limit_exceeded',
    ],
    ['gasLimit 2^64', { gasLimit: 2n ** 64n, gasPrice: 1n }, 'gas_limit_exceeded'],
    ['負の gasPrice', { gasLimit: 21_000n, gasPrice: -1n }, 'gas_limit_exceeded'],
    [
      '個別上限内だが積が既定の総手数料上限を超える',
      { gasLimit: MAX_TX_GAS_LIMIT, gasPrice: MAX_GAS_PRICE_WEI },
      'gas_cost_exceeded',
    ],
  ])('%s は 1021 で拒否する', async (_label, params, phase) => {
    await expect(build(params)).rejects.toMatchObject({ code: '1021', context: { phase } });
  });

  test('通常の見積り（65,000 gas × 30 gwei）は受理する', async () => {
    const tx = await build({ gasLimit: 65_000n, gasPrice: 30n * GWEI });
    expect(tx.gasLimit).toBe(65_000n);
    expect(tx.gasPrice).toBe(30n * GWEI);
  });

  test('混雑時の高値（300 gwei × 200,000 gas ≈ 0.06 ETH）も受理する', async () => {
    await expect(build({ gasLimit: 200_000n, gasPrice: 300n * GWEI })).resolves.toBeDefined();
  });

  test('総手数料はちょうど上限なら受理、1 wei 超なら拒否（呼び出し側の maxTotalCostWei で上書き可）', async () => {
    const params = { gasLimit: 100_000n, gasPrice: 10n * GWEI };
    const cost = params.gasLimit * params.gasPrice;
    await expect(build(params, cost)).resolves.toBeDefined();
    await expect(build(params, cost - 1n)).rejects.toMatchObject({
      code: '1021',
      context: { phase: 'gas_cost_exceeded' },
    });
  });

  test('既定の総手数料上限は 1 ネイティブトークン', () => {
    expect(DEFAULT_MAX_TX_FEE_WEI).toBe(10n ** 18n);
  });

  test('例外にガス値を含めない', async () => {
    const error = await build({ gasLimit: 100_000n, gasPrice: 50_000n * GWEI }).catch((e) => e);
    expect(JSON.stringify({ message: error.message, context: error.context })).not.toContain(
      '50000',
    );
  });
});

describe('signAndSendTransaction: 署名前の最終検査（手組み Tx / 承認後に差し替えられた値）', () => {
  const baseTx: TransactionRequest = {
    to: TOKEN,
    value: 0n,
    data: '0xa9059cbb',
    gasLimit: 65_000n,
    gasPrice: 30n * GWEI,
    nonce: 7,
    chainId: 1,
  };

  function deps(maxTotalCostWei?: bigint) {
    let signCalls = 0;
    const signer: Signer = {
      async sign() {
        signCalls += 1;
        return new Uint8Array(65);
      },
      publicKey: () => new Uint8Array(33),
      address: () => FROM,
    };
    const serializer: TxSerializer = {
      serializeUnsigned: () => new Uint8Array([1]),
      assembleSigned: () => '0xRAW',
    };
    const { callSource, sent } = fakeCallSource(undefined, '0xHASH');
    return {
      deps: { signer, callSource, serializer, maxTotalCostWei },
      signCalls: () => signCalls,
      sent,
    };
  }

  test.each([
    ['gasPrice 50,000 gwei', { gasPrice: 50_000n * GWEI }],
    ['gasLimit 2^64', { gasLimit: 2n ** 64n }],
    ['積が上限超過', { gasLimit: 10_000_000n, gasPrice: 200n * GWEI }],
  ])('%s は署名せず送信もしない（1021）', async (_label, over) => {
    const { deps: d, signCalls, sent } = deps();
    await expect(signAndSendTransaction({ ...baseTx, ...over }, d)).rejects.toMatchObject({
      code: '1021',
    });
    expect(signCalls()).toBe(0);
    expect(sent).toHaveLength(0);
  });

  test('承認時の見積りを maxTotalCostWei として渡せば、署名時の値上がりを拒否する', async () => {
    const approved = baseTx.gasLimit * baseTx.gasPrice;
    const ok = deps(approved);
    await expect(signAndSendTransaction(baseTx, ok.deps)).resolves.toBe('0xHASH');
    const raised = deps(approved);
    await expect(
      signAndSendTransaction({ ...baseTx, gasPrice: baseTx.gasPrice + 1n }, raised.deps),
    ).rejects.toMatchObject({ code: '1021', context: { phase: 'gas_cost_exceeded' } });
    expect(raised.signCalls()).toBe(0);
  });

  test('通常の Tx は署名・送信される', async () => {
    const d = deps();
    await expect(signAndSendTransaction(baseTx, d.deps)).resolves.toBe('0xHASH');
    expect(d.signCalls()).toBe(1);
    expect(d.sent).toHaveLength(1);
  });
});
