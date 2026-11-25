/**
 * ERC-1056 controller 設定／削除の「未署名トランザクション」構築。
 *
 * `changeOwner(address identity, address newOwner)`
 * を呼ぶ EVM トランザクションを組み立てる。設定（setController）は新しい owner アドレスへ、
 * 削除（removeController）は identity 自身を owner に戻す（= 委任解除）として表現する。
 *
 * 本モジュールは ethers に直接依存しない。ABI エンコードは `AbiEncoder` シーム経由で注入され、
 * 既定実装は ethers-adapter.ts が提供する。これによりテストはモックエンコーダで完結し、
 * ネットワーク・ethers 実体に依存しない（DI seam）。
 *
 * 実送信（keymanager 署名 + RPC ブロードキャスト）は呼び出し側の責務であり、本モジュールは
 * `to` / `data` / `value` を備えた未署名トランザクションの構築までを担う。
 *
 * セキュリティ上の注意:
 * - 例外メッセージや `context` に DID 文字列・アドレスを含めない。
 */

import { ErrorCodes, VericertsError } from '../errors.js';
import { isValidEvmAddress } from '../evm-format.js';
import { parseEthrDid } from './did-ethr.js';

/**
 * ABI 関数呼び出しを calldata（0x hex 文字列）にエンコードするシーム。
 *
 * 既定実装は ethers の `Interface.encodeFunctionData` を用いる（ethers-adapter.ts）。
 * テストではモックを注入してネットワーク・ethers 実体に依存せず検証する。
 */
export interface AbiEncoder {
  /**
   * 関数名と引数列を calldata にエンコードする。
   *
   * @param functionName ABI 関数名（例: `changeOwner`）。
   * @param args 引数列（アドレス等）。
   * @returns 0x プレフィックス付き calldata hex 文字列。
   */
  encodeFunctionData(functionName: string, args: readonly unknown[]): string;
}

/**
 * 署名前の EVM トランザクション。
 *
 * 実送信時に nonce / gas / chainId 等を補完するのは呼び出し側（keymanager + RPC）の責務。
 */
export interface UnsignedTransaction {
  /** 送信先（ERC-1056 レジストリのコントラクトアドレス）。 */
  readonly to: string;
  /** ABI エンコード済み calldata（`changeOwner(...)`）。 */
  readonly data: string;
  /** 送金額（controller 操作は常に 0）。 */
  readonly value: bigint;
  /** 対象 DID から導出した EVM チェーン ID。 */
  readonly chainId: number;
}

/**
 * controller 操作の Tx 構築に必要な依存。
 */
export interface ControllerTxDeps {
  /** ERC-1056 レジストリのコントラクトアドレス（チェーンごとに異なる）。 */
  readonly registryAddress: string;
  /** ABI エンコーダ（既定は ethers-adapter の `createErc1056AbiEncoder`）。 */
  readonly encoder: AbiEncoder;
}

/** `changeOwner` の ABI 関数名。 */
const CHANGE_OWNER = 'changeOwner';

/**
 * レジストリアドレスの形式を検証する（set / remove 両経路で一貫して一度だけ呼ぶ）。
 *
 * `registryAddress` は入力（DID）ではなく設定値だが、形式不正は Tx を構築できない状態である。
 * 専用のエラーコードは設けず、便宜上 `INVALID_DID`（2001）で設定値不正を表す。
 *
 * @param registryAddress ERC-1056 レジストリのコントラクトアドレス。
 * @throws レジストリアドレス形式不正（設定値不正を便宜上 code `2001` で表す）の場合。
 */
function assertRegistryAddress(registryAddress: string): void {
  if (!isValidEvmAddress(registryAddress)) {
    // レジストリアドレスは設定値であり入力ではないため、形式不正は構築不能として扱う。
    throw new VericertsError(ErrorCodes.INVALID_DID);
  }
}

/**
 * `changeOwner(identity, newOwner)` の未署名トランザクションを構築する内部ヘルパ。
 *
 * レジストリアドレスは set / remove の両経路でここを通すため、本ヘルパで一度だけ検証する。
 *
 * @param identityAddress 対象 identity の 0x アドレス。
 * @param newOwnerAddress 新しい owner の 0x アドレス。
 * @param chainId 対象チェーン ID。
 * @param deps レジストリアドレスと ABI エンコーダ。
 * @returns 未署名トランザクション（to=レジストリ、data=encodeFunctionData 結果）。
 * @throws レジストリアドレス形式不正（設定値不正を便宜上 code `2001` で表す）の場合。
 */
function buildChangeOwnerTx(
  identityAddress: string,
  newOwnerAddress: string,
  chainId: number,
  deps: ControllerTxDeps,
): UnsignedTransaction {
  assertRegistryAddress(deps.registryAddress);
  const data = deps.encoder.encodeFunctionData(CHANGE_OWNER, [identityAddress, newOwnerAddress]);
  return {
    to: deps.registryAddress,
    data,
    value: 0n,
    chainId,
  };
}

/**
 * controller を設定する未署名トランザクションを構築する（setController）。
 *
 * ERC-1056 では DID の owner（= controller）の付け替えを `changeOwner(identity, newOwner)` で
 * 行う。`did`（identity）の owner を `controllerDid` のアドレスへ変更する Tx を返す。
 *
 * @param did 対象の did:ethr 文字列。
 * @param controllerDid 新しい controller の did:ethr 文字列。
 * @param deps レジストリアドレスと ABI エンコーダ。
 * @returns 未署名トランザクション。
 * @throws DID 形式不正・レジストリアドレス形式不正（いずれも便宜上 code `2001`）の場合
 *         （VericertsError）。レジストリアドレス検証は `buildChangeOwnerTx` で一度だけ行う。
 */
export function buildSetControllerTx(
  did: string,
  controllerDid: string,
  deps: ControllerTxDeps,
): UnsignedTransaction {
  const identity = parseEthrDid(did);
  const controller = parseEthrDid(controllerDid);
  return buildChangeOwnerTx(identity.address, controller.address, identity.chainId, deps);
}

/**
 * controller を削除する未署名トランザクションを構築する（removeController）。
 *
 * ERC-1056 には controller 解除専用の関数はないため、owner を identity 自身に戻す
 * `changeOwner(identity, identity)` を委任解除として表現する。
 *
 * 設定済み controller の検証（2006）は実行前に検出ロジック（events.ts）で行う前提とし、
 * 念のため `controllerDid` が現在想定する controller のアドレスかの整合確認はここでは行わない
 * （オンチェーン状態は呼び出し側が検出済み）。
 *
 * @param did 対象の did:ethr 文字列。
 * @param deps レジストリアドレスと ABI エンコーダ。
 * @returns 未署名トランザクション（owner を identity 自身に戻す）。
 * @throws DID 形式不正・レジストリアドレス形式不正（いずれも便宜上 code `2001`）の場合
 *         （VericertsError）。レジストリアドレス検証は `buildChangeOwnerTx` で一度だけ行う。
 */
export function buildRemoveControllerTx(did: string, deps: ControllerTxDeps): UnsignedTransaction {
  const identity = parseEthrDid(did);
  // owner を identity 自身に戻す = controller を持たない状態（自己所有）に復帰。
  // レジストリアドレスの検証は buildChangeOwnerTx 内で行う（set と一貫）。
  return buildChangeOwnerTx(identity.address, identity.address, identity.chainId, deps);
}
