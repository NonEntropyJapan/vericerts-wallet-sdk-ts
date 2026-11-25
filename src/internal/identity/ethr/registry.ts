/**
 * did:ethr の ERC-1056 DID Registry へのイベント取得層。
 *
 * 本モジュールと `log-decode.ts`（応答ログの検証・ABI デコード）に **ethers.js への依存を閉じ込める**。
 * 他の ethr モジュール（events.ts / method-ethr.ts）はネットワーク非依存で、本ファイルが提供する
 * `Erc1056EventSource` シーム経由でイベントを受け取る。テストはこのシームを
 * モック注入することで ethers / network に触れずに検証する。
 *
 * セキュリティ上の注意:
 * - 取得は `http/json-rpc.ts` の `requestJsonRpc`（10 秒タイムアウト・1 MiB 本文上限・redirect 非追従）で
 *   行う。ethers の `JsonRpcProvider` は既定 300 秒・本文上限なしで、攻撃者が自分の identity に大量の
 *   イベントを発行するだけで署名検証前の解決が数秒停止し GB 級のヒープを消費した。ログ件数も
 *   {@link MAX_ERC1056_EVENTS} で打ち切る。
 * - RPC URL・アドレス・DID などの入力や ethers の原因例外（cause）を
 *   VericertsError の message / cause に伝播させない。
 */

import { zeroPadValue } from 'ethers';
import { ErrorCodes, VericertsError } from '../../errors.js';
import type { FetchLike } from '../../fetch-di.js';
import { requestJsonRpc } from '../../http/json-rpc.js';
import {
  assertResolutionWorkRemaining,
  consumeResolutionWork,
  type ResolutionWorkBudget,
  WORK_UNITS_PER_EVENT_DECODE,
} from '../resolution-budget.js';
import { consumeResolutionValue } from '../resolution-charge.js';
import { type Erc1056Events, MAX_ERC1056_EVENTS } from './events.js';
import {
  ERC1056_INTERFACE,
  type ErcEventName,
  notFound,
  type RawLog,
  toAttributeChange,
  toOwnerChange,
} from './log-decode.js';

/**
 * ERC-1056 イベントの取得シーム。method-ethr.ts はこのインターフェース経由で
 * イベントを取得し、ethers / network 詳細から切り離される。
 */
export interface Erc1056EventSource {
  /**
   * 指定チェーン・identity の ERC-1056 イベントを取得する。
   *
   * @param chainId チェーン ID。
   * @param address identity アドレス（`0x` + 40 hex）。
   * @param scope 解決スコープ全体の予算。尽きたスコープでは RPC を始めず、取得したログの保持量と
   *   デコード仕事量をデコードの前に計上する。省略時は計上しない。
   * @returns owner / attribute 変更イベント集合。
   * @throws 未設定チェーン・RPC 失敗の場合（VericertsError、code `2003`）、
   *         スコープ予算超過の場合（code `2001`、`context.reason: 'resolution_work_limit'`）。
   */
  fetchEvents(
    chainId: number,
    address: string,
    scope?: ResolutionWorkBudget,
  ): Promise<Erc1056Events>;
}

/**
 * ERC-1056 既定コントラクトアドレス（uPort deterministic deploy）。
 */
export const DEFAULT_REGISTRY_ADDRESS = '0xdca7ef03e98e0dc2b855be647c39abe984fcf21b';

/**
 * チェーン ID → RPC URL のマップ。`createEthersEventSource` に注入する。
 */
type RpcUrls = Readonly<Record<number, string>>;
/**
 * チェーン ID → レジストリコントラクトアドレスのマップ（既定アドレスの上書き用）。
 */
type RegistryAddresses = Readonly<Record<number, string>>;

/**
 * ethers.js の ABI デコーダと `requestJsonRpc` を用いた既定の `Erc1056EventSource` 実装を生成する。
 *
 * チェーンごとに `eth_getLogs` で DIDOwnerChanged / DIDAttributeChanged を取得して
 * `Erc1056Events` に正規化する。2 クエリは並行に発行し、解決全体の上限は 1 往復分（10 秒）に収まる。
 *
 * @param rpcUrls チェーン ID → RPC URL マップ。未設定チェーンは `DID_NOT_FOUND`。
 * @param registryAddresses チェーン ID → レジストリアドレス（省略時は既定アドレス）。
 * @param fetchImpl RPC 往復に使う fetch 実装（省略時はグローバル `fetch`。テスト注入用）。
 * @returns `Erc1056EventSource`。取得失敗・タイムアウト・本文上限超過は `DID_NOT_FOUND`、
 *          ログ件数が {@link MAX_ERC1056_EVENTS} を超える場合は `DID_DOC_INVALID`。
 */
export function createEthersEventSource(
  rpcUrls: RpcUrls,
  registryAddresses?: RegistryAddresses,
  fetchImpl?: FetchLike,
): Erc1056EventSource {
  return {
    async fetchEvents(
      chainId: number,
      address: string,
      scope?: ResolutionWorkBudget,
    ): Promise<Erc1056Events> {
      // `chainId` は DID 由来の数値。`Object.prototype['137']` のような数値キーの汚染が未設定チェーンの
      // RPC URL・レジストリアドレスに化けないよう、自身のプロパティだけを引く。
      const rpcUrl = Object.hasOwn(rpcUrls, chainId) ? rpcUrls[chainId] : undefined;
      if (rpcUrl === undefined) {
        // 未設定チェーンは解決不能（入力 RPC マップ内容は伝播しない）。
        throw notFound();
      }
      // 尽きたスコープでは RPC 往復自体を始めない。
      assertResolutionWorkRemaining(scope, 0);
      const registryAddress =
        (registryAddresses !== undefined && Object.hasOwn(registryAddresses, chainId)
          ? registryAddresses[chainId]
          : undefined) ?? DEFAULT_REGISTRY_ADDRESS;
      const query = (id: number, eventName: ErcEventName): Promise<readonly RawLog[]> =>
        queryLogs(rpcUrl, fetchImpl, id, registryAddress, eventName, address);
      try {
        const [ownerLogs, attributeLogs] = await Promise.all([
          query(1, 'DIDOwnerChanged'),
          query(2, 'DIDAttributeChanged'),
        ]);
        // 件数上限はデコード（ABI パース・オブジェクト生成）の前に両クエリ合計で課す。
        if (ownerLogs.length + attributeLogs.length > MAX_ERC1056_EVENTS) {
          throw new VericertsError(ErrorCodes.DID_DOC_INVALID);
        }
        // 相異なる DID を並べた増幅の上限として、保持するログ量とデコード仕事量をデコードの前にスコープへ計上する。
        consumeResolutionValue(scope, [ownerLogs, attributeLogs]);
        consumeResolutionWork(
          scope,
          (ownerLogs.length + attributeLogs.length) * WORK_UNITS_PER_EVENT_DECODE,
        );
        const expected = { registry: registryAddress, identityTopic: zeroPadValue(address, 32) };
        return {
          ownerChanges: ownerLogs.flatMap((log) => toOwnerChange(log, expected)),
          attributeChanges: attributeLogs.flatMap((log) => toAttributeChange(log, expected)),
        };
      } catch (error) {
        // ethers / RPC の原因例外は秘密を含み得るため cause を伝播しない。
        // 件数上限超過（2010）とスコープ予算超過（2001）は呼び出し側が「取得失敗」と区別できるようそのまま通す。
        if (
          error instanceof VericertsError &&
          (error.code === ErrorCodes.DID_DOC_INVALID || error.code === ErrorCodes.INVALID_DID)
        ) {
          throw error;
        }
        throw notFound();
      }
    },
  };
}

/**
 * `eth_getLogs` で `identity` の指定イベントを全期間取得する（トピックフィルタ: event signature + indexed identity）。
 *
 * 応答は `requestJsonRpc` が 10 秒・1 MiB で打ち切る。`result` が配列でなければ取得失敗として扱う。
 */
async function queryLogs(
  rpcUrl: string,
  fetchImpl: FetchLike | undefined,
  id: number,
  registryAddress: string,
  eventName: ErcEventName,
  identity: string,
): Promise<readonly RawLog[]> {
  const topic0 = ERC1056_INTERFACE.getEvent(eventName)?.topicHash;
  if (topic0 === undefined) {
    // ABI に必ず含まれるため実際には到達しない。
    throw notFound();
  }
  const result = await requestJsonRpc(
    rpcUrl,
    fetchImpl,
    id,
    'eth_getLogs',
    [
      {
        address: registryAddress,
        topics: [topic0, zeroPadValue(identity, 32)],
        fromBlock: '0x0',
        toBlock: 'latest',
      },
    ],
    ErrorCodes.DID_NOT_FOUND,
  );
  if (!Array.isArray(result)) {
    throw notFound();
  }
  return result as readonly RawLog[];
}
