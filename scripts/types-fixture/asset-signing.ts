// SDK が名前を公開しない RPC 契約の 3 型（レジストリの `derive` 分類）を、公開済みの
// `EvmCallSource` から導出できること、導出結果が extension の使う構造型と一致することを検査する consumer。
// 公開 entry（`@vericerts/vericerts-wallet-sdk/asset`）以外は import しない。
//   (a) 元型の構造を literal で書き下し、導出型と双方向に代入する（SDK 側で構造が変われば落ちる）。
//   (b) 導出が any / never に潰れると (a) は素通りするので、潰れていないことを別に固定する。
import type { EvmCallSource } from '@vericerts/vericerts-wallet-sdk/asset';

type EvmSendRequest = Parameters<EvmCallSource['send']>[0];
type EvmTxEstimate = Parameters<EvmCallSource['fetchTxParams']>[2];
type EvmTxParams = Awaited<ReturnType<EvmCallSource['fetchTxParams']>>;

type SendRequestShape = { readonly chainId: number; readonly rawTransaction: string };
type TxEstimateShape = { readonly to: string; readonly data: string; readonly value: bigint };
type TxParamsShape = {
  readonly nonce: number;
  readonly gasLimit: bigint;
  readonly gasPrice: bigint;
};

declare const sendRequest: EvmSendRequest;
declare const sendShape: SendRequestShape;
declare const txEstimate: EvmTxEstimate;
declare const estimateShape: TxEstimateShape;
declare const txParams: EvmTxParams;
declare const paramsShape: TxParamsShape;

export const sendToShape: SendRequestShape = sendRequest;
export const sendFromShape: EvmSendRequest = sendShape;
export const estimateToShape: TxEstimateShape = txEstimate;
export const estimateFromShape: EvmTxEstimate = estimateShape;
export const paramsToShape: TxParamsShape = txParams;
export const paramsFromShape: EvmTxParams = paramsShape;

type IsAny<T> = 0 extends 1 & T ? true : false;
type IsNever<T> = [T] extends [never] ? true : false;

export const sendNotAny: false = null as unknown as IsAny<EvmSendRequest>;
export const sendNotNever: false = null as unknown as IsNever<EvmSendRequest>;
export const estimateNotAny: false = null as unknown as IsAny<EvmTxEstimate>;
export const estimateNotNever: false = null as unknown as IsNever<EvmTxEstimate>;
export const paramsNotAny: false = null as unknown as IsAny<EvmTxParams>;
export const paramsNotNever: false = null as unknown as IsNever<EvmTxParams>;
