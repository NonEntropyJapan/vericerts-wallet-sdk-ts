/**
 * 手数料予算 `maxTotalCostWei` の汚染耐性・型検証。
 *
 * `deps.maxTotalCostWei` を素で読むと、`Object.prototype.maxTotalCostWei` に汚染値（`Infinity` /
 * 文字列 / `NaN` / 巨大 bigint 以外）が仕込まれた状態で予算を省略した呼び出しが、汚染値を「指定された予算」
 * として拾う。`bigint` と非 `bigint` の比較は例外にならず常に偽になるため、総手数料上限が黙って無効化される。
 * 呼び出し側が**明示した**不正値（`NaN` / `Infinity` / 文字列 / 負値）も同様に無効化するので型で拒否する。
 */

import { describe, expect, test } from 'bun:test';
import { withPollutedPrototypeAsync } from '../../../__tests__/prototype-pollution.fixtures.js';
import type { Signer } from '../../../keymanager/keymanager.js';
import {
  buildTransferTx,
  signAndSendTransaction,
  type TransactionRequest,
  type TxSerializer,
} from '../../erc20-tx.js';
import { MAX_GAS_PRICE_WEI, MAX_TX_GAS_LIMIT } from '../../tx-fee-limits.js';
import { fakeCallSource, fakeCodec } from '../erc20/erc20-tx.fakes.js';

const TOKEN = '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48';
const TO = '0x70997970C51812dc3A010C7d01b50e0d17dc79C8';
const FROM = '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266';

/** 個別上限内だが積が既定の総手数料上限（1 ETH）を超える RPC 応答。 */
const OVER_BUDGET = { gasLimit: MAX_TX_GAS_LIMIT, gasPrice: MAX_GAS_PRICE_WEI };

/** 予算を無効化する汚染値 / 不正値の形状。 */
const INVALID_BUDGETS: readonly [string, unknown][] = [
  ['Infinity', Number.POSITIVE_INFINITY],
  ['NaN', Number.NaN],
  ['数値', 10 ** 30],
  ['文字列', '1'],
  ['空文字列', ''],
  ['オブジェクト', {}],
  ['null', null],
  ['負の bigint', -1n],
];

function build(params: { gasLimit: bigint; gasPrice: bigint }, extra: object = {}) {
  const { codec } = fakeCodec();
  const { callSource } = fakeCallSource({ nonce: 1, ...params });
  return buildTransferTx(1, FROM, TO, 1n, TOKEN, { codec, callSource, ...extra });
}

const baseTx: TransactionRequest = {
  to: TOKEN,
  value: 0n,
  data: '0xa9059cbb',
  gasLimit: OVER_BUDGET.gasLimit,
  gasPrice: OVER_BUDGET.gasPrice,
  nonce: 7,
  chainId: 1,
};

function signDeps(extra: object = {}) {
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
  return { deps: { signer, callSource, serializer, ...extra }, signCalls: () => signCalls, sent };
}

describe('buildTransferTx の maxTotalCostWei 汚染耐性', () => {
  test.each(
    INVALID_BUDGETS,
  )('予算を省略しても汚染値（%s）で総手数料上限は無効化されない（汚染前後で同じ拒否）', async (_label, polluted) => {
    const clean = await build(OVER_BUDGET).catch((e) => e);
    expect(clean).toMatchObject({ code: '1021', context: { phase: 'gas_cost_exceeded' } });
    const result = await withPollutedPrototypeAsync({ maxTotalCostWei: polluted }, () =>
      build(OVER_BUDGET).catch((e) => e),
    );
    expect(result.code).toBe(clean.code);
    expect(result.context).toEqual(clean.context);
  });

  test.each(
    INVALID_BUDGETS,
  )('明示された不正な予算（%s）は上限を無効化せず 1021 gas_budget_invalid で拒否する', async (_label, bad) => {
    await expect(build(OVER_BUDGET, { maxTotalCostWei: bad })).rejects.toMatchObject({
      code: '1021',
      context: { phase: 'gas_budget_invalid' },
    });
    // 上限内の見積りでも不正な予算は黙って無視せず拒否する（予算無しで署名させない）。
    await expect(
      build({ gasLimit: 21_000n, gasPrice: 1n }, { maxTotalCostWei: bad }),
    ).rejects.toMatchObject({ code: '1021', context: { phase: 'gas_budget_invalid' } });
  });

  test('own の bigint 予算は汚染値より優先され、境界（ちょうど / 1 wei 超）で判定される', async () => {
    const params = { gasLimit: 100_000n, gasPrice: 1_000n };
    const cost = params.gasLimit * params.gasPrice;
    await withPollutedPrototypeAsync({ maxTotalCostWei: Number.POSITIVE_INFINITY }, async () => {
      await expect(build(params, { maxTotalCostWei: cost })).resolves.toBeDefined();
      await expect(build(params, { maxTotalCostWei: cost - 1n })).rejects.toMatchObject({
        context: { phase: 'gas_cost_exceeded' },
      });
    });
  });

  test('0n の予算は有限な非負値として受理され、ガス代ゼロ以外を拒否する', async () => {
    await expect(
      build({ gasLimit: 21_000n, gasPrice: 1n }, { maxTotalCostWei: 0n }),
    ).rejects.toMatchObject({ context: { phase: 'gas_cost_exceeded' } });
  });

  test.each([
    ['gasLimit が number', { gasLimit: 21_000 as unknown as bigint, gasPrice: 1n }],
    ['gasPrice が文字列', { gasLimit: 21_000n, gasPrice: '1' as unknown as bigint }],
    ['gasLimit が NaN', { gasLimit: Number.NaN as unknown as bigint, gasPrice: 1n }],
  ])('RPC 由来のガス値の型不正（%s）は積の比較をすり抜けず拒否する', async (_label, params) => {
    await expect(build(params)).rejects.toMatchObject({
      code: '1021',
      context: { phase: 'gas_limit_exceeded' },
    });
  });
});

describe('signAndSendTransaction の maxTotalCostWei 汚染耐性', () => {
  test.each(
    INVALID_BUDGETS,
  )('予算を省略しても汚染値（%s）で署名前の総手数料検査は無効化されない', async (_label, polluted) => {
    await withPollutedPrototypeAsync({ maxTotalCostWei: polluted }, async () => {
      const d = signDeps();
      await expect(signAndSendTransaction(baseTx, d.deps)).rejects.toMatchObject({
        code: '1021',
        context: { phase: 'gas_cost_exceeded' },
      });
      expect(d.signCalls()).toBe(0);
      expect(d.sent).toHaveLength(0);
    });
  });

  test.each(
    INVALID_BUDGETS,
  )('明示された不正な予算（%s）では署名も送信もしない', async (_label, bad) => {
    const d = signDeps({ maxTotalCostWei: bad });
    await expect(
      signAndSendTransaction({ ...baseTx, gasLimit: 21_000n, gasPrice: 1n }, d.deps),
    ).rejects.toMatchObject({ code: '1021', context: { phase: 'gas_budget_invalid' } });
    expect(d.signCalls()).toBe(0);
    expect(d.sent).toHaveLength(0);
  });

  test('予算を省略した通常の Tx は汚染下でも署名・送信される', async () => {
    await withPollutedPrototypeAsync({ maxTotalCostWei: 0n }, async () => {
      const d = signDeps();
      await expect(
        signAndSendTransaction({ ...baseTx, gasLimit: 65_000n, gasPrice: 30n * 10n ** 9n }, d.deps),
      ).resolves.toBe('0xHASH');
      expect(d.signCalls()).toBe(1);
    });
  });
});
