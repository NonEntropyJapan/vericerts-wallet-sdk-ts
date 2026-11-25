/**
 * ERC-20 送金トランザクションの構築・署名・送信。
 *
 * `buildTransferTx` は `transfer(to, amount)` の calldata を `AbiCodec` seam で組み立て、
 * `EvmCallSource.fetchTxParams` で nonce / gasLimit / gasPrice を補完した `TransactionRequest`
 * を返す。`signAndSendTransaction` は keymanager の `Signer`
 * （生 privateKey 非露出）で署名し、`EvmCallSource.send` 経由でブロードキャストする。
 *
 * Tx のシリアライズ（RLP）と署名の組み立ては `TxSerializer` seam に隔離し、本モジュールは
 * ethers に直接依存しない。署名対象は未署名 Tx のシリアライズバイト列であり、`Signer.sign` が
 * keccak256 + secp256k1 recoverable 署名（65 バイト r||s||v）を計算する。これは EVM の署名ハッシュ
 * （keccak256(serialize(unsignedTx))）と一致する。
 *
 * セキュリティ上の注意:
 * - 例外メッセージや `context` にアドレス・金額・署名済み Tx を含めない。
 * - 秘密鍵は `Signer` を介してのみ扱い、本モジュールでは保持・露出しない。
 */

import { ErrorCodes, VericertsError } from '../errors.js';
import type { Signer } from '../keymanager/keymanager.js';
import { ownProperty } from '../prototype-safety/own-property.js';
import type { AbiCodec } from './codec.js';
import { assertAddress } from './read-utils.js';
import type { EvmCallSource } from './rpc.js';
import { assertTxFeeWithinLimits } from './tx-fee-limits.js';

/** ERC-20 `transfer` の ABI 関数名。 */
const TRANSFER = 'transfer';

/**
 * 署名前後で共通の ERC-20 送金トランザクション。
 *
 * `to` はトークンコントラクト、`value` は 0（ERC-20 transfer はネイティブ送金を伴わない）、
 * `data` は `transfer(recipient, amount)` の calldata。gas / nonce / chainId を含む完全な Tx。
 */
export interface TransactionRequest {
  /** 送信先（トークンコントラクトアドレス）。 */
  readonly to: string;
  /** ネイティブ送金額（ERC-20 transfer では常に 0n）。 */
  readonly value: bigint;
  /** `transfer(recipient, amount)` の ABI エンコード済み calldata（`0x` hex）。 */
  readonly data: string;
  /** ガス上限。 */
  readonly gasLimit: bigint;
  /** legacy gasPrice（wei）。 */
  readonly gasPrice: bigint;
  /** 送信元アカウントの nonce。 */
  readonly nonce: number;
  /** 対象チェーン ID。 */
  readonly chainId: number;
}

/**
 * 署名済み生トランザクションへのシリアライズ seam（ethers 隔離）。
 *
 * 既定実装は ethers-adapter.ts の `createTxSerializer` が `ethers.Transaction` で提供する。
 */
export interface TxSerializer {
  /**
   * 未署名 Tx を RLP シリアライズし、署名対象のバイト列を返す（署名前）。
   *
   * @param tx 補完済み未署名トランザクション。
   * @returns 署名対象のシリアライズバイト列（`Signer.sign` が keccak256 して署名する）。
   * @throws シリアライズ不能の場合（VericertsError、code `1021`）。
   */
  serializeUnsigned(tx: TransactionRequest): Uint8Array;

  /**
   * 未署名 Tx と 65 バイト署名（r||s||v、v は 0/1）から署名済み生トランザクションを組み立てる。
   *
   * @param tx 補完済み未署名トランザクション。
   * @param signature 65 バイト recoverable 署名。
   * @returns 署名済み生トランザクション（`0x` プレフィックス付き hex）。
   * @throws 署名組み立て不能の場合（VericertsError、code `1021`）。
   */
  assembleSigned(tx: TransactionRequest, signature: Uint8Array): string;
}

/**
 * 送金 Tx 構築の依存（DI seam）。
 */
export interface BuildTransferTxDeps {
  /** ABI エンコードシーム（既定は ethers-adapter の `createErc20AbiCodec`）。 */
  readonly codec: AbiCodec;
  /** gas・nonce 取得を行う RPC シーム（既定は ethers-adapter の `createEvmCallSource`）。 */
  readonly callSource: EvmCallSource;
  /** 総手数料（`gasLimit × gasPrice`、wei）の上限。省略時は `DEFAULT_MAX_TX_FEE_WEI`。 */
  readonly maxTotalCostWei?: bigint;
}

/**
 * 送金 Tx の署名・送信の依存（DI seam）。
 */
export interface SignAndSendDeps {
  /** 送金元の鍵に紐づく Signer（keymanager.getSigner の結果）。 */
  readonly signer: Signer;
  /** ブロードキャストを行う RPC シーム。 */
  readonly callSource: EvmCallSource;
  /** 未署名 Tx のシリアライズと署名組み立て（ethers 隔離）。 */
  readonly serializer: TxSerializer;
  /** 総手数料（`gasLimit × gasPrice`、wei）の上限。省略時は `DEFAULT_MAX_TX_FEE_WEI`。 */
  readonly maxTotalCostWei?: bigint;
}

/**
 * ERC-20 送金トランザクションを構築する。
 *
 * `transfer(to, amount)` を ABI エンコードし、`fetchTxParams` で nonce / gasLimit / gasPrice を
 * 補完した完全な `TransactionRequest` を返す。ガス見積もりは送信元 `from` を用いて行う。
 *
 * @param chainId 対象チェーン ID。
 * @param from 送信元アドレス（nonce 取得・ガス見積もりに用いる、`0x` + 40 hex）。
 * @param to 受取人アドレス（`0x` + 40 hex）。
 * @param amount 送金額（最小単位の `bigint`）。
 * @param tokenAddress トークンコントラクトアドレス（`0x` + 40 hex）。
 * @param deps ABI codec / RPC の DI。
 * @returns gas・nonce を補完した送金トランザクション。
 * @throws `from` / `tokenAddress` / `to` のアドレス形式不正（VericertsError、code `4070`）、
 *         ABI エンコード失敗・RPC / ガス見積もり失敗・ガス上限超過（VericertsError、code `1021`）の場合。
 *         引数値は例外に含めない。
 */
export async function buildTransferTx(
  chainId: number,
  from: string,
  to: string,
  amount: bigint,
  tokenAddress: string,
  deps: BuildTransferTxDeps,
): Promise<TransactionRequest> {
  // `from` / `tokenAddress` は codec を通らない（`to` は codec が 4070 で拒否する）ため自前で検証する。
  // 検証しないと `tokenAddress = ''` が `to = null` のコントラクト作成 Tx として署名・送信される。
  assertAddress(from);
  assertAddress(tokenAddress);
  // transfer(recipient, amount) の calldata を組み立てる。不正アドレス・引数は codec が拒否する。
  const data = deps.codec.encode(TRANSFER, [to, amount]);
  // ERC-20 transfer はトークンコントラクト宛・ネイティブ送金額 0。
  const value = 0n;
  const params = await deps.callSource.fetchTxParams(chainId, from, {
    to: tokenAddress,
    data,
    value,
  });
  // RPC 由来のガス値は信頼できない。侵害 RPC によるガス代名目の残高流出を署名前に拒否する。
  assertTxFeeWithinLimits(params, ownProperty<unknown>(deps, 'maxTotalCostWei'));
  return {
    to: tokenAddress,
    value,
    data,
    gasLimit: params.gasLimit,
    gasPrice: params.gasPrice,
    nonce: params.nonce,
    chainId,
  };
}

/**
 * 未署名 Tx に署名して送信し、トランザクションハッシュを返す。
 *
 * 未署名 Tx をシリアライズし（`serializer.serializeUnsigned`）、Signer で署名（`Signer.sign` が
 * keccak256 + secp256k1 recoverable 署名を計算 = EVM の署名ハッシュ）、署名済み生 Tx を組み立てて
 * `callSource.send` でブロードキャストする。
 *
 * @param tx 送金トランザクション（`buildTransferTx` の戻り値、gas / nonce 補完済み）。
 * @param deps Signer / RPC / シリアライザの DI。
 * @returns トランザクションハッシュ（`0x` プレフィックス付き hex）。
 * @throws 署名失敗（code `1020`）・シリアライズ / RPC / 送信失敗（code `1021`）・
 *         `gasLimit` / `gasPrice` / 総手数料の上限超過（code `1021`、署名前に拒否）の場合。
 */
export async function signAndSendTransaction(
  tx: TransactionRequest,
  deps: SignAndSendDeps,
): Promise<string> {
  // 署名前の最終防衛線: 手組みの Tx や RPC 由来のガス値が上限を超えるなら署名しない。
  assertTxFeeWithinLimits(tx, ownProperty<unknown>(deps, 'maxTotalCostWei'));
  // 未署名 Tx の RLP シリアライズ（署名対象バイト列）。失敗は 1021 に正規化される。
  const unsigned = deps.serializer.serializeUnsigned(tx);
  // Signer.sign が keccak256(unsigned) を secp256k1 recoverable 署名する（65 バイト r||s||v）。
  // 署名失敗は Signer 側で VericertsError（1020）に正規化される。
  const signature = await signWithSigner(deps.signer, unsigned);
  // 署名済み生 Tx を組み立て、ブロードキャストする。
  const rawTransaction = deps.serializer.assembleSigned(tx, signature);
  return deps.callSource.send({ chainId: tx.chainId, rawTransaction });
}

/**
 * Signer.sign を呼び、想定外（VericertsError 以外）の例外を署名失敗（1020）に正規化する。
 *
 * Signer 実装由来の例外メッセージには鍵・入力データが含まれ得るため cause は渡さない。
 *
 * @param signer 署名に用いる Signer。
 * @param data 署名対象（未署名 Tx のシリアライズバイト列）。
 * @returns 65 バイト recoverable 署名。
 * @throws 署名失敗の場合（VericertsError、code `1020`）。
 */
async function signWithSigner(signer: Signer, data: Uint8Array): Promise<Uint8Array> {
  try {
    return await signer.sign(data);
  } catch (cause) {
    // Signer が投げた VericertsError（1020 等）はそのまま伝播させる。
    if (cause instanceof VericertsError) {
      throw cause;
    }
    // それ以外は秘密が含まれ得るため cause を渡さず署名失敗に正規化する。
    throw new VericertsError(ErrorCodes.SIGN_FAILED);
  }
}
