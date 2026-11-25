/**
 * `BundlerRpc` の既定実装（fetch ベースの JSON-RPC トランスポート）。
 *
 * bundler.ts は `BundlerRpc` インタフェース経由で通信する。このアダプタと
 * paymaster-fetch-adapter.ts は共通の {@link requestJsonRpc} でリクエストを送信する。
 *
 * ネットワークの往復そのもの（タイムアウト・本文上限・seam 解決・本文解放）は横断の
 * `http/json-rpc.ts` に 1 か所だけ置く。本ファイルが持つのは Bundler 固有の JSON-RPC 呼び出し形と
 * 正規化先のエラーコード（`7002` BUNDLER_REJECTED）だけである。
 */

import { ErrorCodes } from '../errors.js';
import type { FetchLike } from '../fetch-di.js';
import { requestJsonRpc } from '../http/json-rpc.js';
import type { BundlerRpc } from './bundler.js';

/**
 * fetch 相当の最小インターフェース（テスト・非ブラウザ環境での注入用）。
 *
 * 横断の {@link FetchLike}（`internal/fetch-di.ts`）をそのまま使う。本文の上限読み出し
 * （`readBodyWithinLimit`）とタイムアウト（`init.signal`）は `Response` と `AbortSignal` を要求する
 * ため、aa 専用の別定義を持つと「片方だけ弱い」状態になる。
 *
 * 注入する実装が `this` 参照を持つ（`class Deps { fetchImpl() { … this.agent … } }` 形の）場合は、
 * **呼び出し側が渡す前に自分で束ねること**。ここへは関数値しか渡らず、元のオブジェクトは失われている
 * （`http/fetch-json.ts` と同じ制約）。
 */
export type { FetchLike };

/** JSON-RPC リクエスト ID の連番カウンタ用の初期値。 */
const INITIAL_ID = 1;

/**
 * fetch ベースの `BundlerRpc` を生成する。
 *
 * @param url Bundler の JSON-RPC エンドポイント URL。
 * @param fetchImpl fetch 実装（未指定はグローバル `fetch`。テストで注入可能）。
 * @returns `BundlerRpc` 実装。
 */
export function createFetchBundlerRpc(url: string, fetchImpl?: FetchLike): BundlerRpc {
  let nextId = INITIAL_ID;
  return {
    request(method: string, params: readonly unknown[]): Promise<unknown> {
      return requestJsonRpc(url, fetchImpl, nextId++, method, params, ErrorCodes.BUNDLER_REJECTED);
    },
  };
}
