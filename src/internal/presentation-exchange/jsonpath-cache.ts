/**
 * `jsonpath-plus` の静的キャッシュ `JSONPath.cache` の上限化。
 *
 * `jsonpath-plus` はモジュール静的な 1 つのオブジェクトに、式ごとの
 * Script / AST（キー `<eval クラスのソース>Script:<式>`）と path 文字列ごとの分解結果（`toPathArray`）を
 * 上限・追い出し無しで保持する。`field.path` は Verifier 由来の非信頼入力で、Presentation Request を受けるたびに
 * Verifier が選んだ文字列がプロセス寿命のあいだ溜まり続けていた（0.8 MB の PD 1 件で約 6 MiB が GC 後も残る）。
 * `path-budget.ts` の予算は 1 リクエスト内の評価量だけを縛り、リクエストをまたぐ保持量は縛らない。
 *
 * `JSONPath.cache` を、書き込みごとに件数を数え、上限に達したら全消去する置換オブジェクト（`Proxy`）へ
 * 差し替える。正当な PD の path は高々数十種類なので、上限を超えるのは攻撃（または極端に多様な PD）だけで、
 * 全消去しても再計算するだけ（fail-open にならない）。保持量は上限件数 × 1 件の大きさ（path 長は構造検証で 512 以下）に
 * 収まり、リクエスト件数に依らない。土台は `null` プロトタイプにして、`__proto__` / `constructor` / `toString`
 * 等の path で `Object.prototype` の値が「キャッシュ済み」と誤読されないようにする。
 */

import { JSONPath } from 'jsonpath-plus';
import { ownProperty } from '../prototype-safety/own-property.js';

/** `JSONPath.cache` に保持してよい最大件数（超えたら全消去）。 */
export const MAX_JSONPATH_CACHE_ENTRIES = 512;

let installed = false;

/** 上限つきキャッシュを作る。`set` で新しいキーが上限に達していたら先に全消去する。 */
function createBoundedCache(): Record<string, unknown> {
  const store: Record<string, unknown> = Object.create(null);
  let size = 0;
  return new Proxy(store, {
    set(target, key, value) {
      if (typeof key !== 'string') {
        return false;
      }
      if (!Object.hasOwn(target, key)) {
        if (size >= MAX_JSONPATH_CACHE_ENTRIES) {
          for (const existing of Object.keys(target)) {
            delete target[existing];
          }
          size = 0;
        }
        size += 1;
      }
      target[key] = value;
      return true;
    },
    deleteProperty(target, key) {
      if (typeof key === 'string' && Object.hasOwn(target, key)) {
        size -= 1;
      }
      return Reflect.deleteProperty(target, key);
    },
  });
}

/**
 * `JSONPath.cache` を上限つきのものへ差し替える（プロセスで 1 度だけ。評価の前に呼ぶ）。
 *
 * extension の PEx スタブ（評価エンジンに到達しない）は `cache` を持たないため、その場合は何もしない。
 */
export function ensureBoundedJsonPathCache(): void {
  if (installed) {
    return;
  }
  const holder = JSONPath as unknown as { cache?: unknown };
  const cache = ownProperty<unknown>(holder, 'cache');
  if (typeof cache !== 'object' || cache === null) {
    return;
  }
  holder.cache = createBoundedCache();
  installed = true;
}
