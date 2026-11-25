/**
 * ERC-1056 controller（所有者）関係のオンチェーン検出。
 *
 * `DIDOwnerChanged(identity, owner, previousChange)` イベントを走査して identity の
 * 現在の owner（= controller）を判定する。
 *
 * イベント取得は did:ethrの `Erc1056EventSource` シーム（ethr/registry.ts）を
 * **そのまま再利用**して注入する。既定実装は ethr/registry.ts の `createEthersEventSource`
 * が `queryFilter` で提供する。これによりイベント取得層を did:ethr と共有し、テストは
 * モック EventSource で完結してネットワーク・ethers 実体に依存しない。
 *
 * controller 連鎖の解決:
 * - 各 identity の owner を順にたどり、最終的な「自己所有でない最上位 owner」を controller とする。
 * - owner の連鎖は **同一 chainId 上** でたどる（クロスチェーン委任は対象外）。
 * - 連鎖中に既訪問の identity に戻った場合は循環参照（`CONTROLLER_CHAIN_LOOP`、code `2030`）。
 * - owner が一度も設定されていない（イベントなし）かつ controller 未設定の問い合わせは
 *   `CONTROLLER_NOT_AUTHORIZED`（code `2006`）。
 *
 * セキュリティ上の注意:
 * - 例外メッセージや `context` に DID 文字列・アドレスを含めない。
 */

import { ErrorCodes, VericertsError } from '../errors.js';
import { createEthersEventSource, type Erc1056EventSource } from '../identity/ethr/registry.js';
import {
  consumeResolutionWork,
  createResolutionWorkBudget,
  type ResolutionWorkBudget,
  WORK_UNITS_PER_OWNER_LOOKUP,
} from '../identity/resolution-budget.js';
import { type EthrDidParts, formatEthrDid } from './did-ethr.js';

// did:ethr のイベント取得シームをそのまま再利用する（重複実装を持たない）。
export { createEthersEventSource, type Erc1056EventSource };

/**
 * owner 連鎖をたどる最大段数（起点から数えた owner 委任の数）。
 *
 * 正当な委任は「個人 → 組織 → 親会社」程度の 1〜3 段で、1 段ごとに `eth_getLogs` が 2 本（最大 10 秒・1 MiB）飛ぶ。
 * 上限が無いと、攻撃者が自分で用意した N 段の owner 連鎖（アドレスは無料で作れる）を指す DID を 1 つ渡すだけで、
 * 1 回の `detectController` が 2N 回の RPC を逐次に発行する。上限超過は予算超過と同じ
 * `INVALID_DID`（`context.reason: 'resolution_work_limit'`）で拒否する。
 */
export const MAX_CONTROLLER_CHAIN_DEPTH = 4;

/** アドレスの大文字小文字差を無視して比較するための正規化。 */
function normalizeAddress(address: string): string {
  return address.toLowerCase();
}

/**
 * 1 つの identity の現在の owner を判定する。
 *
 * ethr の `fetchEvents` が返す `ownerChanges`（DIDOwnerChanged）を `blockNumber`→`logIndex`
 * 昇順に整列し、最後の owner を採用する。イベントが 1 件も無い場合は ERC-1056 の既定どおり
 * owner は identity 自身（= 未委任）とみなす。
 *
 * @param parts 対象 identity（chainId + アドレス）。
 * @param source イベント取得シーム（ethr/registry.ts の `Erc1056EventSource`）。
 * @param scope 仕事量の予算（イベントのデコードぶんは `fetchEvents` が計上する）。
 * @returns 現在の owner アドレス（イベントなしなら identity 自身のアドレス）。
 */
async function resolveCurrentOwner(
  parts: EthrDidParts,
  source: Erc1056EventSource,
  scope: ResolutionWorkBudget,
): Promise<string> {
  const { ownerChanges } = await source.fetchEvents(parts.chainId, parts.address, scope);
  if (ownerChanges.length === 0) {
    // ERC-1056 既定: owner 未設定の identity は自己所有。
    return parts.address;
  }
  const sorted = [...ownerChanges].sort(
    (a, b) => a.blockNumber - b.blockNumber || a.logIndex - b.logIndex,
  );
  // 整列後の末尾が現在の owner。length>0 を確認済みのため必ず存在する。
  const latest = sorted[sorted.length - 1];
  return latest === undefined ? parts.address : latest.owner;
}

/**
 * did:ethr の controller 連鎖をたどり、最終的な controller を判定する。
 *
 * identity の owner をたどり、owner が identity 自身（自己所有）になった時点を終端とする。
 * 終端 identity が起点と異なる場合、その識別子を controller として返す。起点が自己所有
 * （owner = 自分自身）の場合は controller 未設定とみなし `CONTROLLER_NOT_AUTHORIZED`（2006）。
 *
 * 連鎖の途中で既に訪問済みの identity に戻った場合は循環参照として
 * `CONTROLLER_CHAIN_LOOP`（2030）を投げる。
 *
 * controller 連鎖は起点と同一の chainId 上でのみたどる（owner を別チェーンの identity と
 * みなすクロスチェーン委任は対象外）。
 *
 * 連鎖は最大 {@link MAX_CONTROLLER_CHAIN_DEPTH} 段までで、1 段ごとに RPC 往復ぶんの仕事量
 * （{@link WORK_UNITS_PER_OWNER_LOOKUP}）を **取得の前に** `scope` へ計上する。
 *
 * @param start 起点 identity（chainId + アドレス）。
 * @param source イベント取得シーム（モック可能）。
 * @param scope 仕事量の予算。省略時は呼び出しごとに新しい既定予算を作る（呼び出し 1 回の総量を縛る）。
 * @returns 現在の controller を表す did:ethr 文字列。
 * @throws controller 未設定（code `2006`）／循環参照（code `2030`）／段数・予算超過
 *         （code `2001`、`context.reason: 'resolution_work_limit'`）の場合（VericertsError）。
 */
export async function detectController(
  start: EthrDidParts,
  source: Erc1056EventSource,
  scope: ResolutionWorkBudget = createResolutionWorkBudget(),
): Promise<string> {
  const visited = new Set<string>([normalizeAddress(start.address)]);
  let current: EthrDidParts = start;
  // 取得済みの owner 照会の回数（= 起点を 0 段目としてたどった段数）。
  let lookups = 0;

  // owner をたどる。自己所有に到達したら終端。各反復で current.address を起点に owner を
  // 引き、未訪問なら次の identity に進む。終端は return（controller 確定）/ throw（2006/2030）で
  // 表現し、`visited` により必ず有限回で停止する（毎反復で新規アドレスを 1 つ追加するため）。
  for (;;) {
    // 段数上限と RPC 往復ぶんの仕事量は、往復を始める **前に** 払う（取得してから数えると、上限を超える往復が
    // 先に飛んでしまう）。`lookups` が段数上限を超える 5 回目の照会は発行しない。
    if (lookups > MAX_CONTROLLER_CHAIN_DEPTH) {
      throw new VericertsError(ErrorCodes.INVALID_DID, {
        context: { reason: 'resolution_work_limit' },
      });
    }
    consumeResolutionWork(scope, WORK_UNITS_PER_OWNER_LOOKUP);
    lookups += 1;
    const owner = await resolveCurrentOwner(current, source, scope);
    const ownerKey = normalizeAddress(owner);

    if (ownerKey === normalizeAddress(current.address)) {
      // 自己所有に到達 = 連鎖の終端。
      if (normalizeAddress(current.address) === normalizeAddress(start.address)) {
        // 起点が自己所有 = controller が一切設定されていない。
        throw new VericertsError(ErrorCodes.CONTROLLER_NOT_AUTHORIZED);
      }
      return formatEthrDid(current);
    }

    if (visited.has(ownerKey)) {
      // 既訪問の identity に戻った = 循環参照。
      throw new VericertsError(ErrorCodes.CONTROLLER_CHAIN_LOOP);
    }
    visited.add(ownerKey);
    // owner は同一チェーン上の identity として連鎖をたどる。
    current = { chainId: current.chainId, address: owner };
  }
}
