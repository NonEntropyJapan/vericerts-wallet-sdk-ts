/**
 * GET 1 本ぶんの `fetch` シーム（`fetch-di.ts` の `FetchLike` を GET 用に読み替える）。
 *
 * **配置**: `internal/http/`。JSON 文書取得（`fetch-json.ts`）のほか Credential Manifest 取得
 * （`credential/manifest/parse.ts`）と通知ポーリング（`credential/notification/poll.ts`）が
 * 同じ読み替えを必要とする。経路ごとに書き写すと、片方だけが body 付きに戻っても誰も気付かない。
 */

import type { FetchLike } from '../fetch-di.js';

/**
 * HTTP GET 1 本に必要な最小限の `fetch` シグネチャ（init に `body` を持たない）。
 *
 * **GET に `body` を持たせてはならない。** `new Request(url, { method: 'GET', body: '' })` は
 * Node/undici とブラウザで `TypeError: Request with GET/HEAD method cannot have body.` になり、
 * 空文字でも例外になる。Bun の `fetch` だけがこれを許容するため、スタブを注入するテストでは
 * 一切表面化せず、**実 fetch を使う本番経路だけが 1 度もネットワークへ到達しない**という形で
 * 壊れる（SDK のビルド target は browser）。
 *
 * {@link FetchLike} との差は init の `body` の有無だけである。注入点（`fetchImpl`）は共有する。
 */
export type GetFetchLike = (
  input: string,
  init: {
    method: string;
    headers: Record<string, string>;
    signal: AbortSignal;
  },
) => Promise<Response>;

/**
 * 注入された `FetchLike` を GET 用に読み替える。
 *
 * `FetchLike` の init は POST 経路に合わせて `body: string` を必須にしているため、`body` を
 * 持たない GET の init は構造的にそれより狭く、TypeScript の契約上そのままでは渡せない。
 * 型を緩める（`body?: string` にする）ほうが素直だが、それは `init.body` を `string` として
 * 読んでいる既存の注入実装をすべて `string | undefined` 読みへ直す変更になるため、読み替えを
 * **この 1 か所**に閉じる。GET のスタブが `init.body` を読む理由は無く、読んでも `undefined` に
 * なるだけである。
 *
 * @param doFetch `fetch-di.ts` の `resolveInjectedFetch` が解決した実装。
 * @returns 同じ関数を GET 用シグネチャとして見た view。
 */
export function asGetFetch(doFetch: FetchLike): GetFetchLike {
  return doFetch as GetFetchLike;
}
