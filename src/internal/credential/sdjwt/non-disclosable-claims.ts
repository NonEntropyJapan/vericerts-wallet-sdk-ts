/**
 * SD-JWT VC で選択的開示の対象にしないクレーム集合。
 *
 * `sdjwt.ts` から切り出している。判定そのものは 1 つの `Set` だが、根拠（標準の MUST NOT と
 * 本 SDK 独自のハードニングの切り分け）を正確に残す必要があり、`sdjwt.ts` の行数上限を
 * 圧迫するため独立モジュールにした。
 */

/**
 * 選択的開示の対象にしない登録済み JWT クレーム。
 *
 * `disclosureClaims` に指定されても Disclosure へは回さず、常に平文 payload に残す。
 *
 * 根拠は 2 段階に分かれる。混同しないこと:
 *
 * 1. **標準の要求**: `draft-ietf-oauth-sd-jwt-vc` §2.2.2.3 は `iss` / `nbf` / `exp` / `cnf` /
 *    `vct` / `vct#integrity` / `aka_vcts` / `status` を選択的開示の対象にしては**ならない**
 *    （MUST NOT）と定める。
 * 2. **本 SDK 固有のハードニング**: 同 §2.2.2.3 は `sub` と `iat` については選択的開示を
 *    **許容している**（MAY）。それでも本 SDK が `iat` を非開示にするのは、隠せると
 *    未来 `iat` のクロックスキュー判定（4014）と FC-11 の発行時刻解決を同時に無効化できる
 *    ためであり、標準の要求ではなく本実装の追加制約である。
 *
 * 隠せる仕様にすると **クレームを Disclosure へ回す = 平文から消す = 検証をスキップさせる** が
 * 成立する。検証側の `assertTimeClaims` は「クレームが存在しなければ評価しない」設計
 * （`iat` を持たない既存 VC との後方互換）なので、隠された時刻クレームは無言で素通りする:
 *
 * - `iat` を隠す → 未来 `iat` のクロックスキュー判定（4014）と FC-11 の発行時刻解決が消える。
 * - `exp` を隠す → 期限切れ判定（3024 `VC_EXPIRED`）が消え、実質無期限の VC になる。
 * - `nbf` を隠す → 未発効判定（3025 `VC_NOT_YET_VALID`）が消える。
 * - `aka_vcts` / `vct#integrity` を隠す → `vct` に紐づく型の宣言が issuer-signed payload から消え、
 *   Holder が提示から外すだけで Verifier の型照合を回避できる。
 * - `iss` / `vct` / `cnf` / `status` を隠す → 発行者・型・Holder バインド・失効参照が
 *   issuer-signed payload から消え、それぞれに紐づくガードが対象なしで素通りする。
 *
 * `sub` は本集合に含めない（標準が MAY としており、本 SDK の検証経路も `sub` の有無で
 * 判定を変えないため、非開示にする根拠が無い）。
 *
 * 構造クレーム（`_sd` / `_sd_alg`）も同じ理由で対象外にする（Disclosure へ回すと `_sd` 自体が
 * 上書き・二重化され、digest 照合が壊れる）。
 *
 * ## `constructor` を収録しない判断
 *
 * `__proto__` と並ぶ `Object.prototype` のメンバである `constructor` を本集合に加えるべきか
 * 検討したが、**加えない**。本集合は「選択的開示にすると検証がスキップされるクレーム」を
 * 列挙するものであり、`constructor` はそのいずれにも当たらないためである。
 *
 * - **復元側は既に安全**: `recoverClaims` は復元先へ `Object.defineProperty` でクレームを
 *   置く（`claims.ts` の `defineClaim`）。`constructor` という名前でも通常の own データ
 *   プロパティが作られ、`Object.prototype.constructor` を書き換えることも、復元結果の
 *   プロトタイプを差し替えることもない。`__proto__` が危険だったのは素朴な代入が own
 *   プロパティを作らずプロトタイプを差し替えたからで、`constructor` にその挙動は無い。
 * - **重複検知も素通りしない**: 同名クレームの衝突検知は `Object.hasOwn` で行うため、
 *   `constructor` の own プロパティを正しく検出する（`'constructor' in claims` なら
 *   継承値に当たって誤検知したが、その読み方はしていない）。
 * - **判定表自体が汚染されない**: 本集合は `Set` であり、`NON_DISCLOSABLE_CLAIMS.has(name)` は
 *   プロトタイプ鎖を辿らない。`obj[name]` 形式の対応表なら `constructor` が truthy に化けたが、
 *   `Set` ではその経路が無い。
 *
 * 逆に収録すると、`constructor` という名前のクレームだけが選択的開示できなくなる（標準が
 * 禁じていない制約を本 SDK が独自に課す）。塞ぐべき欠陥が無い以上、その副作用は正当化できない。
 */
export const NON_DISCLOSABLE_CLAIMS: ReadonlySet<string> = new Set([
  'iat',
  'exp',
  'nbf',
  'iss',
  'vct',
  'vct#integrity',
  'aka_vcts',
  'cnf',
  'status',
  '_sd',
  '_sd_alg',
]);
