/**
 * `loadTrustedList` の `options.nowSeconds` 検証（trust/etsi-tsl）。
 *
 * `etsi-tsl.ts` から切り出したのは Linterly の 1 ファイル 300 行上限に収めるためで、責務自体は
 * 単純（own 限定の読み取り + 型検証）だが独立してテストしやすい単位でもある。
 *
 * `?? systemNowSeconds()` は `null` / `undefined` しか拾わないため、`NaN` や文字列などの型不正値が
 * そのまま下流に流れていた。影響は二つ: (1) 失効判定（`ttl-cache.ts` の
 * `now >= entry.expiresAtSeconds`）が `NaN >= x` で常に `false` になり、期限切れキャッシュを
 * 「有効期限内」と誤判定して FO-5 の対象を不当に拡大する。(2) 取得成功時の
 * `new Date(nowSeconds * 1000).toISOString()` が非有限値で生の `RangeError` を投げる（
 * 同じバグクラス）。
 *
 * `Number.isFinite` だけでは不十分な点にも注意する。エポック秒は本来整数であり、`storeTrustedListCache`
 * の TTL 計算（`nextUpdateSeconds - nowSeconds`）は `nextUpdateSeconds` が整数のため、`nowSeconds` が
 * 有限だが非整数（例 `1.5`）だと TTL も非整数になり、`ttl-cache.ts` の `assertTtlSeconds` が
 * `VericertsError(VC_SCHEMA_INVALID)` を投げて成功パスをクラッシュさせる。したがって `Number.isInteger`
 * で検証する（有限性は整数性に含まれるため、これ単体で NaN / Infinity / 非整数のいずれも弾ける）。
 *
 * `Number.isInteger` だけでも不十分な点にも注意する（同種の不具合を防ぐ）。
 * `1e13` や `-1e13` は整数だが `Date` が扱える値域（`0` 〜 `MAX_EPOCH_SECONDS`、後述）を超えており、
 * 取得成功時の `new Date(nowSeconds * 1000).toISOString()` が生の `RangeError` を投げる。したがって
 * 整数性に加えて値域（0 以上、`Date` が扱える上限以下）も検証する。
 *
 * 負値は `new Date(...)` 自体には有効な値（例: `new Date(-1000)`）だが、エポック秒として負になる
 * 正当なユースケースは無いため下限を 0 とする。ただし、この値域チェックで `ttl-cache.ts` の
 * `now >= expiresAtSeconds` による FO-5 の誤判定（期限切れキャッシュを「有効期限内」と誤判定する
 * こと）そのものを塞げるわけではない点に注意する。`nowSeconds: 0` のような値域内の過去時刻を渡され
 * ても同じ誤判定は起こり得る（呼び出し元は任意の過去時刻を渡せるため、この誤判定は値域チェックでは
 * 原理的に塞げない）。ここで塞ぐのは値域外による生の `RangeError` と、明白に不正な負値のみである。
 *
 * 不正値は例外（fail-closed）ではなく実時計へフォールバックする。`nowSeconds` は元々省略可能で
 * 実時計が既定のため、型不正・値域外な明示値も「未指定」と同等に扱うのが一貫している
 * （`eudi/wua/obtain.ts` と同じ own 限定 + 型検証の規律）。
 */

import { systemNowSeconds } from '../../../cache/index.js';
import { ownProperty } from '../../../prototype-safety/own-property.js';

/**
 * `nowSeconds` として許容する上限（エポック秒）。
 *
 * `Date` が扱える time value の上限は ECMA-262 の仕様上 `±8_640_000_000_000_000` ミリ秒であり、
 * これをエポック秒に換算した `8_640_000_000_000` 秒（正方向）を上限とする。
 */
const MAX_EPOCH_SECONDS = 8_640_000_000_000;

/**
 * `options.nowSeconds` を own 限定で読み、整数かつ `Date` が扱える値域（0 以上・エポック秒として
 * 妥当）の場合のみ採用する。
 *
 * @param options 呼び出し元のオプション（`nowSeconds` を own プロパティとして持ち得る任意オブジェクト）。
 * @returns 有効な `nowSeconds`、無ければ実時計（エポック秒）。
 */
export function resolveNowSeconds(options: object): number {
  const raw = ownProperty<unknown>(options, 'nowSeconds');
  const valid =
    typeof raw === 'number' && Number.isInteger(raw) && raw >= 0 && raw <= MAX_EPOCH_SECONDS;
  return valid ? raw : systemNowSeconds();
}
