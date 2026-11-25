/**
 * Entity Statement 取得失敗時に代替 JWT を問い合わせる接点（FO-6 のキャッシュ層側の受け口）。
 *
 * `statement-cache.ts` から切り出しているのは `status-list-fail-open.ts` と同じ理由で、
 * キャッシュ層本体（TTL の根拠・negative cache の境界を説明する JSDoc）を圧迫せずに fail-open の
 * 受け口を足せるようにするためである。
 *
 * 本モジュールに**判定は無い**。フックが設定されているか、フックが代替 JWT を返したかだけを見る。
 * FO-6 を許可してよいかの判定（override / 時間上限 / 同意 / 監査記録）は
 * `entity-configuration-fail-open.ts` が `resolveFailOpen` へ委ねる。
 */

import { VericertsError } from '../../../errors.js';
import { OVERSIZED_BODY_REASON } from '../../../http/body-limit.js';
import { ownProperty } from '../../../prototype-safety/own-property.js';

/**
 * 取得失敗が**トランスポート失敗ではなくコンテンツ失敗**か判定する（FO-6 の入力から外す）。
 *
 * `5011 FEDERATION_FETCH_FAILED` は「取得先が今は応答しない」ことを表し、FO-6 を駆動できる唯一の
 * 入力である（`entity-configuration-fail-open.ts`）。ところが本文のバイト上限超過
 * （`http/body-limit.ts` の 1 MiB）も同じコードで送出されるため、そのままでは**攻撃者が制御する
 * エンティティが FO-6 を任意に作り出せる**: 一度は正当な Entity Configuration を返してキャッシュを
 * 作らせ、以後 1 MiB 超を返すだけで、fail-closed ではなく陳腐化した Statement が復活する。
 *
 * 上限超過は取得そのものは成立している「内容の問題」であり、`TRUST_CHAIN_INVALID`（5010）側と
 * 同じ扱い ＝ fail-open の窓へ入れない。判定を本モジュールに置くのは、live な送出経路と
 * negative cache から再送出される経路の**両方**がここを通るためである。
 *
 * @param error 送出予定の取得失敗。
 * @returns 上限超過（`oversized_body`）由来なら `true`。
 */
function isContentFailure(error: unknown): boolean {
  if (!(error instanceof VericertsError)) {
    return false;
  }
  // `context` は `VericertsError` が own プロパティとして持つ。汚染された `Object.prototype.context`
  // を拾って正当な取得失敗を fail-closed 側へ倒さないよう own 限定で読む。
  const context = ownProperty<Record<string, unknown>>(error, 'context');
  return context !== undefined && ownProperty<unknown>(context, 'reason') === OVERSIZED_BODY_REASON;
}

/** 取得失敗の文脈（`StatementFetchFailureHook` への入力）。 */
export interface StatementFetchFailure {
  /** `fetchJwt` が投げた、または negative cache に記憶されていたエラー。 */
  readonly error: unknown;
  /** キャッシュに残っている TTL 切れの JWT。エントリ自体が無ければ `undefined`。 */
  readonly staleJwt: string | undefined;
  /** 現在時刻（エポック秒。`CachedStatementRequest.nowSeconds` と同じ値）。 */
  readonly nowSeconds: number;
}

/** 取得失敗時に代替 JWT を返すフック。`undefined` を返すと元の失敗がそのまま送出される。 */
export type StatementFetchFailureHook = (
  failure: StatementFetchFailure,
) => Promise<string | undefined>;

/**
 * 取得失敗をフックへ渡し、代替 JWT が返ればそれを検証して返す。
 *
 * 代替 JWT も `request.verify` を必ず通す。「キャッシュ命中・ミスに依らず毎回再検証する」という
 * キャッシュ層の不変条件を fail-open 経路でだけ緩めてはならないためで、期限切れ・署名不成立の
 * Statement は FO-6 が成立していても通らない。
 *
 * フックは**自身のプロパティに限って**読む。`request` は SDK 内部が組み立てるオブジェクト
 * リテラルのみで、プロトタイプメソッドとして与えられる余地が無い一方（＝ `ownProperty` で
 * 取りこぼさない）、`Object.prototype` が汚染されると `onFetchFailure` を設定していない
 * `subordinate.ts` の取得失敗まで代替 JWT で救われてしまう。古い Subordinate Statement の
 * 差し戻しは鍵無効化宣言（FC-11）の伝播を止めるため、ここは own 限定で断つ。
 *
 * @param request フック・検証関数・現在時刻（`CachedStatementRequest` が構造的に適合する）。
 * @param error 送出予定の取得失敗。
 * @param staleJwt TTL 切れのキャッシュ済み JWT（エントリが無ければ `undefined`）。
 * @returns 代替 JWT の検証結果。
 * @throws フック未設定 / 代替が返らない場合、および `error` がコンテンツ失敗（上限超過）の場合は
 *         `error` をそのまま。`verify` の例外もそのまま。
 */
export async function failOrSubstitute<T>(
  request: {
    readonly onFetchFailure?: StatementFetchFailureHook;
    readonly verify: (jwt: string) => { readonly value: T };
    readonly nowSeconds: number;
  },
  error: unknown,
  staleJwt: string | undefined,
): Promise<T> {
  if (isContentFailure(error)) {
    // 内容の問題は FO-6 の入力にしない。フックを呼ばないので監査記録も時間上限の消費も起きない。
    throw error;
  }
  const hook = ownProperty<StatementFetchFailureHook>(request, 'onFetchFailure');
  const substitute =
    hook === undefined
      ? undefined
      : await hook({ error, staleJwt, nowSeconds: request.nowSeconds });
  if (substitute === undefined) {
    throw error;
  }
  return request.verify(substitute).value;
}
