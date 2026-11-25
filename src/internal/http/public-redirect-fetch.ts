/**
 * リダイレクトを**ホップごとに**公開 HTTPS 宛へ縛って追従する GET（横断ヘルパー）。
 *
 * 取得先ドメインを攻撃者が選べる経路（did:web / did:webvh）は、最終 URL のスキームだけを
 * 見る `redirect: 'follow'` だと「公開ホスト → 302 → `https://10.0.0.5/`」を追随してしまい、内部
 * ホストへ GET が飛ぶ（blind SSRF / ポート走査）。本ヘルパーは `redirect: 'manual'` で 1 ホップずつ
 * 受け取り、`Location` を {@link isPublicHttpsUrl} で検査してから次のホップを取りに行く。
 *
 * **ブラウザ系ランタイムの制約（fail-closed）**: `redirect: 'manual'` はブラウザでは
 * `opaqueredirect`（`status: 0`、`Location` 不可視）を返し、ホップを検査できない。`redirect: 'follow'`
 * で取り直すと中間ホップ（`https://10.0.0.5/` 等）へ GET が送出済みになり本ヘルパーの目的を失うため、
 * `opaqueredirect` は**再取得せず失敗**させる（`opaque_redirect`）。ブラウザではリダイレクトを返す
 * ホストは取得できない（リダイレクトを追従できるのは `Location` を読める Node / Bun 系ランタイムのみ）。
 */

import type { FetchLike } from '../fetch-di.js';
import { discardBody } from './body-limit.js';
import { isPublicHttpsUrl } from './public-https-url.js';

/** 追従するリダイレクトの最大ホップ数。 */
export const MAX_PUBLIC_REDIRECTS = 5;

const REDIRECT_STATUSES: ReadonlySet<number> = new Set([301, 302, 303, 307, 308]);

/**
 * リダイレクトの**検査による拒否**（非公開 / 非 HTTPS 宛・ホップ数超過・`Location` 不正・
 * `opaqueredirect`）を表す。`fetchFn` 自身が投げるネットワークエラー / abort と呼び出し側が
 * 区別できるようにする（区別が無いと検査起因の拒否が「到達不能」として扱われ、
 * 到達不能時だけ許すフォールバックの迂回路になる）。`message` は固定識別子で URL を含まない。
 */
export class PublicRedirectRejection extends Error {
  constructor(reason: string) {
    super(reason);
    this.name = 'PublicRedirectRejection';
  }
}

/**
 * DI 解決済みの fetch（`resolveInjectedFetch` の `doFetch` / `receiver`）を、
 * {@link fetchFollowingPublicRedirects} が受け取る `typeof fetch` 形へ束ねる。
 *
 * 呼び出しは `doFetch.call(receiver, …)` の形を保ち、`this` 参照つき prototype メソッド実装と
 * グローバル `fetch`（レシーバを束ねない）の双方を壊さない。GET に `body` は載せない。
 */
export function bindForPublicRedirects(
  doFetch: FetchLike,
  receiver: object | undefined,
): typeof fetch {
  return ((input: string, init: Parameters<FetchLike>[1]) =>
    doFetch.call(receiver, input, init)) as unknown as typeof fetch;
}

/**
 * 公開 HTTPS 宛のリダイレクトだけを追従して GET する（詳細は本ファイル冒頭）。
 *
 * @param fetchFn 取得に使う fetch 実装。
 * @param url 最初の取得先（HTTPS かつ公開ホストでなければ fetch せずに拒否する）。
 * @param init `redirect` 以外の fetch オプション。
 * @returns 非リダイレクト応答（リダイレクト先の URL は `Response.url` に反映されるとは限らない）。
 *   最終 URL が要る呼び出し側は {@link fetchFollowingPublicRedirectsWithFinalUrl} を使う。
 * @throws {@link PublicRedirectRejection} 非公開 / 非 HTTPS 宛（初回・中間ホップ）・ホップ数超過・`Location` 不正・
 *   `opaqueredirect` の場合。`fetchFn` が投げた例外（ネットワークエラー / abort）はそのまま伝わる。
 *   呼び出し側は fetch 失敗として正規化する（URL は例外に載せない）。
 */
export async function fetchFollowingPublicRedirects(
  fetchFn: typeof fetch,
  url: string,
  init: Omit<RequestInit, 'redirect'>,
): Promise<Response> {
  return (await fetchFollowingPublicRedirectsWithFinalUrl(fetchFn, url, init)).response;
}

/**
 * {@link fetchFollowingPublicRedirects} と同じだが、最終ホップの URL も返す。
 *
 * 応答を組み直す DI fetch やモックは `Response.url` が空になる。呼び出し側が origin 束縛などを
 * 最終 URL に課すとき、空の `Response.url` の代わりに本ヘルパーが実際に辿った URL を使えるようにする。
 */
export async function fetchFollowingPublicRedirectsWithFinalUrl(
  fetchFn: typeof fetch,
  url: string,
  init: Omit<RequestInit, 'redirect'>,
): Promise<{ response: Response; finalUrl: string }> {
  let current = url;
  for (let hop = 0; hop <= MAX_PUBLIC_REDIRECTS; hop += 1) {
    if (!isPublicHttpsUrl(current)) {
      throw new PublicRedirectRejection('non_public_url');
    }
    const response = await fetchFn(current, { ...init, redirect: 'manual' });
    if (response.type === 'opaqueredirect') {
      discardBody(response);
      throw new PublicRedirectRejection('opaque_redirect');
    }
    if (!REDIRECT_STATUSES.has(response.status)) {
      return { response, finalUrl: current };
    }
    const location = response.headers.get('location');
    discardBody(response);
    if (location === null) {
      throw new PublicRedirectRejection('missing_location');
    }
    // 相対 Location は現在の URL 基準で解決する。
    try {
      current = new URL(location, current).toString();
    } catch {
      throw new PublicRedirectRejection('invalid_location');
    }
  }
  throw new PublicRedirectRejection('too_many_redirects');
}
