/**
 * Asset ドメインの公開エクスポート面の回帰テスト。
 *
 * `internal/asset/erc20-tx.ts` は ERC-20 送金 Tx の構築・署名・送信（`buildTransferTx` /
 * `signAndSendTransaction` / `TxSerializer`）を実装済みで internal バレルにも
 * re-export 済みだが、公開バレル `src/exports/asset.ts` には一切現れず、残高参照のみが
 * 公開されていた。
 *
 * このテストは送金系シンボルがメインバレル（`src/index.ts`）経由で import でき、
 * 実際に動作することを固定する。
 */

import { describe, expect, test } from 'bun:test';
import * as sdk from '../../index.js';
import type { Signer } from '../../internal/keymanager/keymanager.js';

const TOKEN = '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48';
const TO = '0x70997970C51812dc3A010C7d01b50e0d17dc79C8';
const FROM = '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266';
const CHAIN_ID = 1;

describe('公開エクスポート: Asset 送金 API', () => {
  test('buildTransferTx / signAndSendTransaction / createTxSerializer がメインバレルから import できる', () => {
    expect(typeof sdk.buildTransferTx).toBe('function');
    expect(typeof sdk.signAndSendTransaction).toBe('function');
    expect(typeof sdk.createTxSerializer).toBe('function');
  });

  test('公開された buildTransferTx / signAndSendTransaction が実際に動作する（型だけの再エクスポートではない）', async () => {
    const codecCalls: { fn: string; args: readonly unknown[] }[] = [];
    const codec: sdk.AbiCodec = {
      encode(fn, args) {
        codecCalls.push({ fn, args });
        return '0xa9059cbb';
      },
      decode() {
        throw new Error('not used');
      },
    };

    const sent: { chainId: number; rawTransaction: string }[] = [];
    const callSource: sdk.EvmCallSource = {
      call: () => {
        throw new Error('not used');
      },
      nativeBalance: () => {
        throw new Error('not used');
      },
      fetchTxParams: async () => ({ nonce: 7, gasLimit: 65000n, gasPrice: 1_000_000_000n }),
      send: async (req) => {
        sent.push(req);
        return '0xhash';
      },
    };

    const tx: sdk.TransactionRequest = await sdk.buildTransferTx(
      CHAIN_ID,
      FROM,
      TO,
      1_000_000n,
      TOKEN,
      { codec, callSource },
    );
    expect(tx.to).toBe(TOKEN);
    expect(tx.nonce).toBe(7);
    expect(codecCalls[0]?.fn).toBe('transfer');

    const serializer: sdk.TxSerializer = {
      serializeUnsigned: () => new Uint8Array([1, 2, 3]),
      assembleSigned: () => '0xsignedraw',
    };
    const signer: Signer = {
      sign: async () => new Uint8Array(65),
      publicKey: () => new Uint8Array(33),
      address: () => FROM,
    };

    const txHash = await sdk.signAndSendTransaction(tx, { signer, callSource, serializer });
    expect(txHash).toBe('0xhash');
    expect(sent[0]?.rawTransaction).toBe('0xsignedraw');
  });
});
