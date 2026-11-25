/**
 * HTTP 経路が共有する `fetchImpl` DI（テスト注入 seam）の型と解決。
 *
 * **配置**: `src/internal` 直下の横断ヘルパー。
 * 元は `auth/oid4vci/`（Protocol）にあったが、`credential`（Domain）の manifest / notification /
 * refresh 経路が `FetchLike` と `resolveInjectedFetch` を参照しており Domain → Protocol の
 * 逆方向依存になっていた。プロトコル固有の要素を持たない純粋な DI 解決なので横断へ移した。
 * 依存は `own-property.ts` の 1 つだけである。
 *
 * `pushAuthorizationRequest`（`oid4vci/par/par.ts`）と `requestCredential`（`oid4vci.ts`）は
 * どちらも「呼び出し側が任意で渡す `fetchImpl`、省略時はグローバル `fetch`」という同一の
 * 解決を行う。両モジュールとも 1 ファイルの行数が Linterly の 300 行の目安に迫っており、
 * かつこの解決は条件が 1 つずれるだけで壊れる（後述）ため、
 * 片方だけ直った状態を作らないよう共有化する。
 *
 * 参照実装は `credential/refresh/refresh-endpoint.ts`で、そこで
 * 言語化された次の 2 点をそのまま踏襲する。
 *
 * 1. **`fetchImpl` を own 限定で読んではならない。** `class Deps { async fetchImpl(u, i) {…} }`
 *    のように prototype メソッドとして実装するのは正当な DI であり（`own-property.ts`
 *    「どちらのヘルパーを使うか」）、own 限定で読むと「未指定」と判定され、注入した
 *    証明書ピンニング付き `fetch` が**無言でグローバル `fetch` に差し替わる**（例外にならない
 *    ため呼び出し側は差し替えを検知できない）。一方でプロトタイプ鎖をそのまま辿ると、
 *    `Object.prototype` 汚染下で `fetchImpl` を**指定していない**正当な呼び出しが攻撃者の
 *    fetch を掴み、リクエスト本文（PAR では client_assertion）ごと攻撃者へ渡る。
 *    そこで {@link nonObjectPrototypeProperty} で `Object.prototype` 由来だけを弾く。
 * 2. **取り出した関数は取り出し元をレシーバに束ね直して呼ぶ。** 裸で呼ぶと、従来
 *    `req.fetchImpl(url, init)` で成立していた `this` 参照つき実装（接続プールや
 *    ピンニング設定をインスタンスに持つ fetch など）が壊れる。一方でグローバル `fetch` は
 *    `this` を差し替えるとブラウザの WebIDL ブランドチェックで `Illegal invocation` の
 *    TypeError になるため、**グローバル `fetch` にはレシーバを束ねない**。これは未指定時の
 *    フォールバックだけの話ではない。呼び出し側が `fetchImpl: globalThis.fetch` と**素の
 *    グローバル `fetch` を明示注入**するのも正当な使い方であり、そこでレシーバを束ねると
 *    呼び出し側の try/catch が TypeError を `ISSUER_COMMUNICATION_FAILED`(3004, 再試行可) へ
 *    正規化し、**幻の通信障害**として見える。そこで注入の有無ではなく「解決した関数が
 *    グローバル `fetch` そのものか」で束ねるかを決める（Bun / Node の `fetch` は `this` を
 *    検査しないため、この事故が表面化するのはブラウザだけで、テストでは
 *    レシーバが束ねられていないことを直接観測する）。
 *
 * 「注入されたか」の判定は **`injected` の一箇所だけ**で行い、呼ぶ関数とレシーバの双方を
 * そこから導く。`candidate ?? fetch`（`null` もグローバルへ倒れる）と `candidate === undefined`
 * のように条件がずれていると、`fetchImpl = null`（型のない JS からの呼び出しでは有り得る）で
 * 「グローバル `fetch` に呼び出し元をレシーバとして束ねる」組み合わせが成立し、ブラウザでは
 * `Illegal invocation` の TypeError となって通信失敗へ潰れる。関数でない値（未指定・`null`・
 * 汚染された文字列など）はすべて「未注入」として扱う。
 *
 * 本モジュール自身は上記 1 か所以外にプロトタイプ鎖読みを増やさない。
 */

import { nonObjectPrototypeProperty } from './prototype-safety/own-property.js';

/**
 * HTTP POST 1 本に必要な最小限の `fetch` シグネチャ。
 *
 * OID4VCI（`auth`）のほか、Credential Manifest / Notification / refreshService（`credential`）が
 * 共有する。`typeof fetch` だとランタイム固有の拡張（Bun の `preconnect` 等）まで要求してしまい、テストの
 * スタブ注入や標準 fetch 以外の実装が渡しにくい。POST 1 本に必要な範囲だけを型として要求する。
 * **init の `body` は POST 前提であり GET では渡してはならない**（`http/get-fetch.ts` の
 * `GetFetchLike` / `asGetFetch`）。GET に body を載せると Node/undici とブラウザは `Request`
 * 構築の時点で `TypeError: Request with GET/HEAD method cannot have body.` を投げる。
 */
export type FetchLike = (
  input: string,
  init: {
    method: string;
    headers: Record<string, string>;
    body: string;
    signal: AbortSignal;
    redirect?: RequestRedirect; // POST は `'manual'`（`http/public-https-url.ts`）
  },
) => Promise<Response>;

/** 解決済みの `fetch` 実装と、それを呼ぶときのレシーバの組。 */
export interface InjectedFetch {
  /** 実際に呼ぶ fetch 実装。 */
  readonly doFetch: FetchLike;
  /** `doFetch.call(receiver, ...)` に渡すレシーバ。グローバル fetch のときは undefined。 */
  readonly receiver: object | undefined;
}

/**
 * `source.fetchImpl` を DI として解決する（`Object.prototype` 由来の値は採用しない）。
 *
 * 呼び出し側は必ず `doFetch.call(receiver, url, init)` の形で呼ぶこと（裸呼び出しは
 * prototype メソッド実装の `this` を壊す）。
 *
 * @param source `fetchImpl` を読み取る対象（`PARRequest` / `RequestCredentialOptions` 等）。
 * @returns 関数が注入されていればその実装と `source`。ただし注入された値がグローバル `fetch`
 *          そのものの場合と、関数が注入されていない場合はグローバル `fetch` と `undefined`
 *          （グローバル `fetch` にはレシーバを束ねない）。
 */
export function resolveInjectedFetch(source: object): InjectedFetch {
  const candidate = nonObjectPrototypeProperty<unknown>(source, 'fetchImpl');
  const injected: FetchLike | undefined =
    typeof candidate === 'function' ? (candidate as FetchLike) : undefined;
  // グローバル fetch は FetchLike の上位互換（init は構造的にサブセット）。
  const globalFetch = globalThis.fetch as unknown as FetchLike;
  if (injected === undefined) {
    return { doFetch: globalFetch, receiver: undefined };
  }
  // 明示的に注入された値がグローバル `fetch` そのものなら、未指定時と同じくレシーバを束ねない
  // （束ねるとブラウザの WebIDL ブランドチェックで `Illegal invocation` になり 3004 へ潰れる）。
  return injected === globalFetch
    ? { doFetch: injected, receiver: undefined }
    : { doFetch: injected, receiver: source };
}
