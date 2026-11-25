/**
 * `Erc1271Rpc` の既定実装（fetch ベースの `eth_call` JSON-RPC トランスポート）。
 *
 * ERC-1271 の RPC を扱う本ファイル「のみ」が siwe 系で fetch / ネットワークに
 * 触れる（aa の fetch-adapter.ts と同方針の依存隔離）。siwe.ts は `Erc1271Rpc` seam 経由でのみ通信し、
 * テストは fake seam を注入して本アダプタに依存しない。
 *
 * ネットワークの往復そのもの（タイムアウト・本文上限・seam のレシーバ束縛・本文解放）は横断の
 * `http/json-rpc.ts` に 1 か所だけ置く。本ファイルが持つのは `eth_call` 固有の呼び出し形と
 * `result` の形状検査だけである。かつては aa の双子（fetch-adapter.ts）と別々に往復を実装しており、
 * 以前の対策が aa 側にしか当たらず本ファイルだけが弱いまま残った。
 *
 * セキュリティ上の注意:
 * - RPC URL・アドレス・calldata・レスポンス本文・JSON-RPC error message を VericertsError の
 *   message / context / cause に伝播させない。すべて code `1021`（CHAIN_SUBMIT_FAILED、retriable）に
 *   正規化する（JSON-RPC error 応答も同じ 1021 に倒す）。
 * - 応答本文の上限・タイムアウト・本文解放は `http/json-rpc.ts` の docblock を参照。
 */

import { ErrorCodes, VericertsError } from '../../errors.js';
import type { FetchLike } from '../../fetch-di.js';
import { requestJsonRpc } from '../../http/json-rpc.js';
import type { Erc1271Rpc, Hex } from './siwe.js';

/**
 * fetch 相当の最小インターフェース（テスト・非ブラウザ環境での注入用）。
 *
 * 横断の {@link FetchLike}（`internal/fetch-di.ts`）をそのまま使う。本文の上限読み出しと
 * タイムアウトは `Response` と `AbortSignal` を要求するため、siwe 専用の別定義（`{ ok, json }` の
 * ような弱い戻り値型）を持つと共有硬化がこの経路にだけ効かなくなる。
 */
export type Erc1271FetchLike = FetchLike;

/** JSON-RPC リクエスト ID の連番カウンタ用の初期値。 */
const INITIAL_ID = 1;

/**
 * fetch ベースの `Erc1271Rpc` を生成する。`eth_call`（`latest` ブロック）で ERC-1271 を検証する。
 *
 * @param url EVM チェーンの JSON-RPC エンドポイント URL。
 * @param fetchImpl fetch 実装（未指定はグローバル `fetch`。テストで注入可能）。
 * @returns `Erc1271Rpc` 実装。
 */
export function createFetchErc1271Rpc(url: string, fetchImpl?: Erc1271FetchLike): Erc1271Rpc {
  let nextId = INITIAL_ID;
  return {
    async call(to: string, data: Hex): Promise<Hex> {
      const result = await requestJsonRpc(
        url,
        fetchImpl,
        nextId++,
        'eth_call',
        [{ to, data }, 'latest'],
        // ERC-1271 では相手の JSON-RPC error も「検証できなかった」以上の意味を持たないため、
        // トランスポート失敗と同じ 1021 に倒す（本文は伝播させない）。
        ErrorCodes.CHAIN_SUBMIT_FAILED,
      );
      // `requestJsonRpc` はパース境界で null-prototype 化しているため、`result` を持たない応答で
      // `Object.prototype.result` の汚染値を拾うことはない。
      if (typeof result !== 'string' || !result.startsWith('0x')) {
        throw new VericertsError(ErrorCodes.CHAIN_SUBMIT_FAILED);
      }
      return result as Hex;
    },
  };
}
