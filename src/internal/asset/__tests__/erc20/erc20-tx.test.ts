/**
 * erc20-tx.ts（ERC-20 送金 Tx 構築・署名・送信）のユニットテスト。
 *
 * fake seam（AbiCodec / EvmCallSource / TxSerializer / Signer）を注入し、ethers / ネットワークに
 * 依存せず、構築（calldata 組み立て・gas/nonce 補完）・署名・送信のロジックとエラー正規化を検証する。
 */

import { describe, expect, test } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import type { Signer } from '../../../keymanager/keymanager.js';
import type { AbiCodec } from '../../codec.js';
import {
  type BuildTransferTxDeps,
  buildTransferTx,
  type SignAndSendDeps,
  signAndSendTransaction,
  type TransactionRequest,
  type TxSerializer,
} from '../../erc20-tx.js';
import type { EvmCallSource } from '../../rpc.js';
import { fakeCallSource, fakeCodec } from './erc20-tx.fakes.js';

const TOKEN = '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48';
const TO = '0x70997970C51812dc3A010C7d01b50e0d17dc79C8';
const FROM = '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266';
const CHAIN_ID = 1;

describe('buildTransferTx（Tx 構築 + ガス見積もり）', () => {
  test('transfer calldata を組み立て、gas/nonce を補完した TransactionRequest を返す', async () => {
    const { codec, calls } = fakeCodec('0xCALLDATA');
    const { callSource } = fakeCallSource({
      nonce: 42,
      gasLimit: 80000n,
      gasPrice: 2_000_000_000n,
    });
    const deps: BuildTransferTxDeps = { codec, callSource };

    const tx = await buildTransferTx(CHAIN_ID, FROM, TO, 1000n, TOKEN, deps);

    // calldata は transfer(to, amount) でエンコードされる。
    expect(calls).toEqual([{ fn: 'transfer', args: [TO, 1000n] }]);
    // 送信先はトークンコントラクト、value は 0、calldata は codec 結果。
    expect(tx).toEqual({
      to: TOKEN,
      value: 0n,
      data: '0xCALLDATA',
      gasLimit: 80000n,
      gasPrice: 2_000_000_000n,
      nonce: 42,
      chainId: CHAIN_ID,
    });
  });

  test('ガス見積もりは from とトークンコントラクト宛・value=0 の Tx で行う', async () => {
    const { codec } = fakeCodec('0xDATA');
    const { callSource, fetched } = fakeCallSource();
    await buildTransferTx(CHAIN_ID, FROM, TO, 5n, TOKEN, { codec, callSource });

    expect(fetched).toHaveLength(1);
    expect(fetched[0]).toEqual({
      chainId: CHAIN_ID,
      from: FROM,
      tx: { to: TOKEN, data: '0xDATA', value: 0n },
    });
  });

  test('codec のエンコード失敗（不正アドレス等）はそのまま伝播する', async () => {
    const codec: AbiCodec = {
      encode() {
        throw new VericertsError(ErrorCodes.CHAIN_SUBMIT_FAILED);
      },
      decode() {
        throw new Error('not used');
      },
    };
    const { callSource } = fakeCallSource();
    await expect(
      buildTransferTx(CHAIN_ID, FROM, TO, 1n, TOKEN, { codec, callSource }),
    ).rejects.toMatchObject({ code: '1021' });
  });

  test('RPC（fetchTxParams）失敗は伝播する', async () => {
    const { codec } = fakeCodec();
    const callSource: EvmCallSource = {
      async call() {
        throw new Error('not used');
      },
      async nativeBalance() {
        throw new Error('not used');
      },
      async fetchTxParams() {
        throw new VericertsError(ErrorCodes.CHAIN_SUBMIT_FAILED);
      },
      async send() {
        return '0x';
      },
    };
    await expect(
      buildTransferTx(CHAIN_ID, FROM, TO, 1n, TOKEN, { codec, callSource }),
    ).rejects.toMatchObject({ code: '1021' });
  });
});

describe('signAndSendTransaction（署名・送信）', () => {
  const baseTx: TransactionRequest = {
    to: TOKEN,
    value: 0n,
    data: '0xa9059cbb',
    gasLimit: 65000n,
    gasPrice: 1_000_000_000n,
    nonce: 7,
    chainId: CHAIN_ID,
  };

  /** 65 バイトのダミー署名を返す fake Signer。 */
  function fakeSigner(): { signer: Signer; signed: Uint8Array[] } {
    const signed: Uint8Array[] = [];
    const signature = new Uint8Array(65).fill(0xab);
    return {
      signer: {
        async sign(data) {
          signed.push(data);
          return signature;
        },
        publicKey: () => new Uint8Array(33),
        address: () => FROM,
      },
      signed,
    };
  }

  /** 未署名バイト列を返し、署名と組み合わせて生 Tx を返す fake serializer。 */
  function fakeSerializer(): {
    serializer: TxSerializer;
    assembled: { tx: TransactionRequest; sig: Uint8Array }[];
  } {
    const unsigned = new Uint8Array([1, 2, 3]);
    const assembled: { tx: TransactionRequest; sig: Uint8Array }[] = [];
    return {
      serializer: {
        serializeUnsigned() {
          return unsigned;
        },
        assembleSigned(tx, signature) {
          assembled.push({ tx, sig: signature });
          return '0xSIGNEDRAW';
        },
      },
      assembled,
    };
  }

  test('未署名 Tx を署名し、署名済み生 Tx をブロードキャストして hash を返す', async () => {
    const { signer, signed } = fakeSigner();
    const { serializer, assembled } = fakeSerializer();
    const { callSource, sent } = fakeCallSource(undefined, '0xTXHASH');
    const deps: SignAndSendDeps = { signer, callSource, serializer };

    const hash = await signAndSendTransaction(baseTx, deps);

    expect(hash).toBe('0xTXHASH');
    // 署名対象は未署名 Tx のシリアライズバイト列。
    expect(signed).toEqual([new Uint8Array([1, 2, 3])]);
    // 署名は組み立てに渡される。
    expect(assembled).toHaveLength(1);
    expect(assembled[0]?.sig).toEqual(new Uint8Array(65).fill(0xab));
    // 署名済み生 Tx が正しい chainId でブロードキャストされる。
    expect(sent).toEqual([{ chainId: CHAIN_ID, rawTransaction: '0xSIGNEDRAW' }]);
  });

  test('Signer の VericertsError（署名失敗 1020）はそのまま伝播する', async () => {
    const signer: Signer = {
      async sign() {
        throw new VericertsError(ErrorCodes.SIGN_FAILED);
      },
      publicKey: () => new Uint8Array(33),
      address: () => FROM,
    };
    const { serializer } = fakeSerializer();
    const { callSource } = fakeCallSource();
    await expect(
      signAndSendTransaction(baseTx, { signer, callSource, serializer }),
    ).rejects.toMatchObject({ code: '1020' });
  });

  test('Signer の非 VericertsError 例外は署名失敗（1020）に正規化する', async () => {
    const signer: Signer = {
      async sign() {
        throw new Error('boom');
      },
      publicKey: () => new Uint8Array(33),
      address: () => FROM,
    };
    const { serializer } = fakeSerializer();
    const { callSource } = fakeCallSource();
    await expect(
      signAndSendTransaction(baseTx, { signer, callSource, serializer }),
    ).rejects.toMatchObject({ code: '1020' });
  });

  test('シリアライズ失敗（1021）は伝播する', async () => {
    const { signer } = fakeSigner();
    const serializer: TxSerializer = {
      serializeUnsigned() {
        throw new VericertsError(ErrorCodes.CHAIN_SUBMIT_FAILED);
      },
      assembleSigned() {
        return '0x';
      },
    };
    const { callSource } = fakeCallSource();
    await expect(
      signAndSendTransaction(baseTx, { signer, callSource, serializer }),
    ).rejects.toMatchObject({ code: '1021' });
  });

  test('ブロードキャスト失敗（1021）は伝播する', async () => {
    const { signer } = fakeSigner();
    const { serializer } = fakeSerializer();
    const callSource: EvmCallSource = {
      async call() {
        throw new Error('not used');
      },
      async nativeBalance() {
        throw new Error('not used');
      },
      async fetchTxParams() {
        return { nonce: 0, gasLimit: 0n, gasPrice: 0n };
      },
      async send() {
        throw new VericertsError(ErrorCodes.CHAIN_SUBMIT_FAILED);
      },
    };
    await expect(
      signAndSendTransaction(baseTx, { signer, callSource, serializer }),
    ).rejects.toMatchObject({ code: '1021' });
  });
});
