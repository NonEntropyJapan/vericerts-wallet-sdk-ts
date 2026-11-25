/**
 * スキーマ系 JSON 文書の HTTPS 取得（各経路のエラー正規化）。
 *
 * W3C VC の `credentialSchema` 経路と SD-JWT VC の Type Metadata 経路は**別エコシステム**として
 * 扱うが、「Issuer が指す URL から JSON 文書を安全に取得する」処理は同一のため本モジュールを共有
 * する。両経路で返すエラーコードが異なるため、コードは引数で受け取る。
 *
 * タイムアウト・最終 URL・本文サイズの検査、パース、JSON オブジェクトの判定は
 * well-known Metadata の取得と共通である。取得失敗は呼び出し側が指定したエラーコードで返す。
 *
 * セキュリティ上の注意:
 * - 取得元 URL は VC 由来（`vct` / `credentialSchema`）= 攻撃者が影響し得る値。HTTPS 以外は
 *   取得せず、リダイレクト後も HTTPS にとどまることを最終 URL で確認する（SSRF / 平文降格の防止）。
 * - URL・レスポンス本文を例外メッセージ・`context`・`cause` に含めない。
 * - 応答本文は 1 MiB を上限とし、上限に達した時点で読み取りを打ち切る（メモリ枯渇の防止）。
 */

import type { ErrorCode } from '../../errors.js';
import { VericertsError } from '../../errors.js';
import { type FetchLike, resolveInjectedFetch } from '../../fetch-di.js';
import { type BodyLimitOptions, MAX_DOCUMENT_BYTES } from '../../http/body-limit.js';
import {
  fetchJsonWithinLimits,
  JSON_FETCH_TIMEOUT_MS,
  type JsonFetchReason,
} from '../../http/fetch-json.js';
import { isPublicHttpsUrl } from '../../http/public-https-url.js';

/**
 * スキーマ文書取得のタイムアウト（ミリ秒）。
 *
 * 実体は横断プリミティブ `internal/http/fetch-json.ts` の {@link JSON_FETCH_TIMEOUT_MS} で、
 * 本経路の既存 import パスを保つための別名である。
 */
export const SCHEMA_FETCH_TIMEOUT_MS = JSON_FETCH_TIMEOUT_MS;

/**
 * 受理するレスポンス本文の最大バイト数（1 MiB）。
 *
 * 実体は横断プリミティブ `internal/http/body-limit.ts` の `MAX_DOCUMENT_BYTES` で、本経路の
 * 既存 import パスを保つための別名である。上限値と本文検査は well-known Metadata 取得
 * （`auth/well-known-json/index.ts`）と共有する — 同じ検査を書き写すと片方だけが更新されて
 * 弱くなるため。
 */
export const MAX_SCHEMA_DOCUMENT_BYTES = MAX_DOCUMENT_BYTES;

/** ネットワーク取得を注入するための依存（テストは実 fetch を使わずに注入する）。 */
export interface SchemaFetchDependencies {
  /**
   * `fetch` 互換の取得関数。未指定ならグローバル `fetch` を使う。
   *
   * 型は `typeof fetch` ではなく {@link FetchLike}（横断 `fetch-di.ts`）である。`typeof fetch` は
   * ランタイム固有の拡張（Bun の `preconnect` 等）まで要求するため、`class Deps { fetchImpl() {…} }`
   * のような正当な注入実装が代入できない。GET 1 本に必要な範囲だけを要求する。
   */
  readonly fetchImpl?: FetchLike;
}

/**
 * 値が HTTPS URL か判定する。
 *
 * 横断ヘルパー `internal/https-url.ts` の再エクスポート。判定ロジックはそちらに
 * 集約し、既存の import パス（`./fetch-document.js` / `./index.js` 経由）は後方互換のため維持する。
 */
export { isHttpsUrl } from '../../https-url.js';

/**
 * HTTPS URL から JSON object を取得する。
 *
 * **`auth/well-known-json/index.ts` の `fetchJsonDocument` とは別関数である。** 以前は同名だったが、
 * 引数も戻り型も違うため import 側でどちらを指しているか読み取れなかった（あちらは失敗ファクトリを
 * 受け取り `object` を返す）。取得本体は両者とも `internal/http/fetch-json.ts` を共有する。
 *
 * 失敗理由（`context.reason`）は {@link JsonFetchReason} の固定識別子である。
 *
 * @param url 取得先（HTTPS のみ）。
 * @param errorCode 失敗時に投げる `VericertsError` のコード（経路ごとに異なる）。
 * @param deps `fetchImpl` の注入。
 * @param bodyLimit 本文上限の切り詰めと実バイト数の計上（Type Metadata の総量予算用）。
 * @returns パース済み JSON object。
 * @throws 非 HTTPS / ネットワーク失敗 / タイムアウト / 非 2xx / 非 JSON Content-Type /
 *         本文の 1 MiB 超過 / パース失敗 / object 以外の場合（VericertsError、`errorCode`）。
 */
export async function fetchSchemaJson(
  url: string,
  errorCode: ErrorCode,
  deps: SchemaFetchDependencies = {},
  bodyLimit?: BodyLimitOptions,
): Promise<Record<string, unknown>> {
  if (!isPublicHttpsUrl(url)) {
    throw new VericertsError(errorCode, { context: { reason: 'non_https_url' } });
  }
  const failure = (reason: JsonFetchReason): VericertsError =>
    new VericertsError(errorCode, { context: { reason } });
  // `fetchImpl` は DI 依存なので `resolveInjectedFetch` で読む（内部で
  // `nonObjectPrototypeProperty`）。`deps.fetchImpl` と素の鎖読みにすると、`fetchImpl` を
  // **指定していない**正当な呼び出しが `Object.prototype.fetchImpl` の汚染値を掴み、スキーマ文書の
  // 取得ごと攻撃者へ委譲される（= 検証判断の土台になる文書を差し替えられる）。own 限定
  // （`ownProperty`）では読まない — `class Deps { async fetchImpl() {…} }` のような正当な
  // プロトタイプメソッド実装が「未指定」と判定され、注入した fetch が無言でグローバル
  // `fetch` に差し替わるため。
  //
  // **レシーバはここで束ねる。** `fetchJsonWithinLimits` には関数値しか渡らず、あちらが
  // 束ね直せるのは合成リテラルだけなので（`fetch-json.ts`）、`this` 参照つきクラス DI は
  // 渡す側が `bind` しないと壊れる。グローバル `fetch` には束ねない（`receiver` が
  // `undefined` になる。束ねるとブラウザの WebIDL ブランドチェックで `Illegal invocation`）。
  const { doFetch, receiver } = resolveInjectedFetch(deps);
  const fetchImpl: FetchLike = receiver === undefined ? doFetch : doFetch.bind(receiver);
  const parsed = await fetchJsonWithinLimits(url, fetchImpl, failure, undefined, bodyLimit);
  return parsed as Record<string, unknown>;
}
