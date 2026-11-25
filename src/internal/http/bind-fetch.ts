/**
 * `fetchImpl` シームを**関数値のまま配る入口**のためのレシーバ束縛。
 *
 * **配置**: `internal/http/`。DI の解決規則そのものは
 * `internal/fetch-di.ts` が SoT で、本モジュールはその規則を「シームを受け取ってすぐ呼ぶのではなく、
 * 他所へ配る」側に合わせて包み直しただけである。`fetch-json.ts` の docblock が言う
 * 「**渡す前に自分で束ねること**」の実装がこれにあたるため、規則の説明と同じディレクトリに置く。
 *
 * ## なぜ配る側が束ねるのか
 *
 * {@link resolveInjectedFetch} は `{ doFetch, receiver }` の組を返すので、`doFetch.call(receiver, …)`
 * と書ける場所——つまり**取り出した直後に自分で呼ぶ場所**でしか使えない。`createWallet` のように
 * シームを関数値のまま下流へ配る入口では、組を運べないので受け取り側は元のオブジェクトを知らない
 * （下流の `fetchJsonWithinLimits` が束ね直せるのは合成リテラル `{ fetchImpl }` であって、呼び出し側の
 * DI オブジェクトではない）。したがって
 * `class Deps { eudiFetchImpl() { return this.agent.fetch(…) } }` 形の注入は、**配る側がここで
 * 束ねない限り `this` を失う**。失敗は無言で、各経路の catch が「取得に失敗した」へ正規化するため、
 * 幻の通信障害と区別が付かない。
 */

import { type FetchLike, resolveInjectedFetch } from '../fetch-di.js';
import { nonObjectPrototypeProperty } from '../prototype-safety/own-property.js';

/**
 * `source[key]` を DI として解決し、**レシーバを束ねた関数値**として返す。
 *
 * 束ねる / 束ねないの規則は {@link resolveInjectedFetch} と同一である。特にグローバル `fetch` には
 * 束ねない（束ねるとブラウザの WebIDL ブランドチェックで `Illegal invocation` になり、呼び出し側の
 * catch が幻の通信障害へ正規化する。`fetch-di.ts` の規則 2）。
 *
 * プロトタイプ鎖の読みは {@link nonObjectPrototypeProperty} に閉じ、**1 度だけ**読む（アクセサが
 * 読むたび違う値を返しても、判定した値とそのまま束ねた値が食い違わない）。
 *
 * @param source シームを読み取る対象（`createWallet` の `opts` 等。未検査の外部入力）。
 * @param key 読み取るプロパティ名（`'eudiFetchImpl'` のように経路ごとに異なる）。
 * @returns 束ね済みの fetch 実装。関数が注入されていなければ `undefined`（下流の「未指定なら
 *          グローバル `fetch`」の既定をそのまま働かせる）。
 */
export function bindInjectedFetch(source: object, key: string): FetchLike | undefined {
  const candidate = nonObjectPrototypeProperty<unknown>(source, key);
  if (typeof candidate !== 'function') {
    return undefined;
  }
  // 「グローバル `fetch` そのものか」の判定を 1 か所に閉じるため、解決自体は `fetch-di.ts` に委ねる。
  const { doFetch, receiver } = resolveInjectedFetch({ fetchImpl: candidate });
  return receiver === undefined ? doFetch : doFetch.bind(source);
}
