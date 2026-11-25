/**
 * 外部由来 URL から JSON 文書を取得する共有トランスポート — 横断プリミティブ。
 *
 * 「攻撃者が影響し得る URL から JSON を取る」経路は SDK に複数ある（well-known Metadata /
 * JWT VC Issuer Metadata とその `jwks_uri` / VC JSON Schema / SD-JWT VC Type Metadata）。
 * 本文のサイズと種別は `body-limit.ts` で検査する。ここではタイムアウト、最終 URL の検査、
 * パースと object 判定を共有し、各経路が固有のエラーへ変換する。
 *
 * **HTTPS 検査は呼び出し側に残す。** 「何を HTTPS でなければならない値とみなすか」（発行者識別子か、
 * 組み立て済み URL か）と、その失敗に付ける理由は経路ごとに違うためである。ただしここでも自衛で
 * 再検査し、忘れた呼び出し側が SSRF / 平文降格の入口にならないようにする。
 *
 * **リダイレクトはホップごとに公開 HTTPS 宛へ縛って追従する（`public-redirect-fetch.ts`）。**
 * well-known エンドポイントは実運用で 30x を返すことがあるため追従自体は許すが、`redirect: 'follow'`
 * だと「公開ホスト → 302 → `https://10.0.0.5/`」で内部ホストへ GET が飛ぶ（最終 URL の事後検査では
 * 遅い）。`redirect: 'manual'` で 1 ホップずつ受け取り、`Location` を検査してから次を取りに行く。
 * ブラウザの `opaqueredirect`（`Location` 不可視）はホップを検査できないため取り直さず失敗させる
 * 最終 URL の再検査（{@link finalUrlRejection}）は多層防御として残す。
 *
 * セキュリティ上の注意:
 * - 例外の `context` には固定の識別子（{@link JsonFetchReason}）だけを載せ、URL・レスポンス本文・
 *   `cause` を一切含めない。失敗コードの選択は呼び出し側が渡す `failure` に委ねる。
 * - タイムアウトは**本文読了まで**を 1 つの `AbortController` で覆う（`clearTimeout` は本文を
 *   読み終えてから）。ヘッダだけ先に返して本文を引き延ばす攻撃で無限に待たないため。
 * - パースは `parseJsonWithoutPrototype` を通し、返す文書のプロトタイプを外す。呼び出し側の
 *   `ownProperty` 読みと重ねる多層防御である（`own-property.ts`）。
 */

import { VericertsError } from '../errors.js';
import { type FetchLike, resolveInjectedFetch } from '../fetch-di.js';
import { parseJsonWithoutPrototype } from '../prototype-safety/parse-json.js';
import {
  type BodyLimitOptions,
  declaresOversizedBody,
  discardBody,
  isJsonContentType,
  readBodyWithinLimit,
} from './body-limit.js';
import { isPublicHttpsUrl } from './public-https-url.js';
import {
  bindForPublicRedirects,
  fetchFollowingPublicRedirectsWithFinalUrl,
  PublicRedirectRejection,
} from './public-redirect-fetch.js';

/** 取得のタイムアウト（ミリ秒）。発行者通信と揃えて 10 秒。 */
export const JSON_FETCH_TIMEOUT_MS = 10_000;

/**
 * 取得が失敗した理由（固定識別子）。
 *
 * **本プリミティブを通る経路では、経路ごとに別の文字列を使わない。** 同じ共有検査の失敗が経路に
 * よって `oversized_body` だったり `document_too_large` だったりすると、ログ・テスト・仕様の
 * どれもが「同じ失敗」を突き合わせられない。
 *
 * リポジトリ全体ではまだこの規則が行き渡っていない — `eudi/wua/obtain-http.ts` は独自の POST 取得を
 * 持ち、「JSON だが object でない」失敗に旧来の `not_a_json_object` を使い続けている（本プリミティブ
 * では `invalid_metadata`）。同経路を本プリミティブへ寄せるまで、識別子の一意性は**ここを通る
 * 呼び出し側の範囲**での主張である。
 */
export type JsonFetchReason =
  /** 取得先が HTTPS ではない（fetch は 1 度も発生しない）。 */
  | 'non_https_url'
  /** ネットワークエラー / タイムアウト（abort）。リダイレクト検査による拒否は含まない。 */
  | 'fetch_failed'
  /**
   * リダイレクトの検査による拒否（中間ホップが非公開 / 非 HTTPS・ホップ数超過・`Location` 不正・
   * `opaqueredirect`）。ネットワーク不達ではないので `fetch_failed` と区別する（
   * 到達不能時だけ許すフォールバックが検査起因の拒否を迂回しないため）。
   */
  | 'redirect_rejected'
  /** リダイレクト後の最終 URL が HTTPS を外れた。 */
  | 'insecure_redirect'
  /** リダイレクト後の最終 URL が束縛した origin から出た。 */
  | 'cross_origin_redirect'
  /** 非 2xx 応答。 */
  | 'http_error'
  /** Content-Type が JSON 系（`application/json` / `*+json`）でない。 */
  | 'invalid_content_type'
  /** 本文が上限（{@link import('./body-limit.js').MAX_DOCUMENT_BYTES}）を超えた。 */
  | 'oversized_body'
  /** 本文が JSON として読めない。 */
  | 'invalid_json'
  /** JSON ではあるが object ではない（`null` / 配列 / プリミティブ）。 */
  | 'invalid_metadata';

/** 失敗を呼び出し側のエラーコードへ正規化するファクトリ。 */
export type JsonFetchFailure = (reason: JsonFetchReason) => Error;

/** URL の origin が束縛と一致するか（一致しない / 解釈できないなら拒否理由を返す）。 */
function originRejection(url: string, expectedOrigin: string): 'cross_origin_redirect' | undefined {
  try {
    return new URL(url).origin === expectedOrigin ? undefined : 'cross_origin_redirect';
  } catch {
    return 'cross_origin_redirect';
  }
}

/**
 * 最終 URL が期待どおりか検査する（HTTPS 維持 + 任意の origin 束縛）。
 *
 * **`response.url` が空文字でも `expectedOrigin` の束縛は外さない。** `response.url` は fetch の
 * モックだけでなく、公開 DI（`createWallet({ eudiFetchImpl })`）の実装が
 * `new Response(await r.text(), …)` で応答を組み直した場合にも空になる。そこで束縛ごと
 * 無効化すると、`jwt-vc-issuer.ts` が**セキュリティ制御として**渡している origin 束縛が、
 * 正当な DI を挟むだけで消える。そのため `response.url` が空のときは、
 * `fetchFollowingPublicRedirectsWithFinalUrl` が実際に辿った最終ホップの URLで
 * 束縛を課す（各ホップの公開 HTTPS 検査は追従側で済んでいるので重ねない）。
 *
 * 束縛から外れたときの理由は、リダイレクトの有無にかかわらず `cross_origin_redirect` を使う。
 * 同じ「束縛した origin から出た」失敗に経路ごとの別名を与えない（{@link JsonFetchReason}）。
 *
 * @param requestUrl 実際に辿った最終ホップの URL（`response.url` が空のときの代替）。
 * @returns 拒否理由。問題なければ `undefined`。
 */
function finalUrlRejection(
  requestUrl: string,
  response: Response,
  expectedOrigin: string | undefined,
): 'insecure_redirect' | 'cross_origin_redirect' | undefined {
  if (expectedOrigin !== undefined && response.url.length === 0) {
    return originRejection(requestUrl, expectedOrigin);
  }
  if (response.url.length === 0) {
    return undefined;
  }
  // HTTPS 判定は共有ヘルパーに寄せる。同じファイル内に述語を 2 つ置くと（ここが
  // `startsWith('https://')`、`fetchJsonWithinLimits` の取得前検査が `isHttpsUrl`）、片方だけ
  // 条件がずれて一方の経路だけ非 HTTPS を通す（`https-url.ts` の docblock）。実際に
  // `https://`（ホスト無し）は `startsWith` を通り `isHttpsUrl` では落ちる。
  // 参照は行番号ではなく関数名で書く（行番号はハンクが動くたび黙って陳腐化する）。
  if (!isPublicHttpsUrl(response.url)) {
    return 'insecure_redirect';
  }
  return expectedOrigin === undefined ? undefined : originRejection(response.url, expectedOrigin);
}

/**
 * HTTPS URL から JSON object を取得する。
 *
 * 手順:
 * 1. `url` が HTTPS でなければ**取得せずに**拒否する（`non_https_url`）。
 * 2. `GET {url}` を {@link JSON_FETCH_TIMEOUT_MS} のタイムアウト付きで行う（`fetch_failed`。リダイレクトの
 *    検査拒否は `redirect_rejected`）。
 * 3. リダイレクト後の最終 URL が HTTPS を外れていれば拒否する（`insecure_redirect`）。
 *    `expectedOrigin` を渡した場合は origin がそこから出ていないことも確かめる
 *    （`cross_origin_redirect`）。取得前の URL だけを縛っても、同一 origin の URL が別 origin へ
 *    302 すれば追随してしまい、origin 束縛が実効を持たない。`response.url` を持たない応答
 *    （応答を組み直す DI 実装・モック）では、**追従ヘルパーが返す最終ホップの URL で
 *    origin 束縛を課す**（{@link finalUrlRejection}）。
 * 4. 非 2xx を拒否する（`http_error`）。
 * 5. JSON でない Content-Type を拒否する（`invalid_content_type`）。
 * 6. 本文を 1 MiB 上限で読み（`fetch_failed` / `oversized_body`）、JSON としてパースする
 *    （`invalid_json`）。
 * 7. object でない / `null` / 配列を拒否する（`invalid_metadata`）。
 *
 * `fetchImpl` は必ず**引数**で受け取り、`doFetch.call(receiver, ...)` の形で呼ぶ
 * （横断 `fetch-di.ts`）。ただし**ここで束ね直せるレシーバは合成した `{ fetchImpl }` であって、
 * 呼び出し側の DI オブジェクトそのものではない** — 関数値しか渡らないので元のオブジェクトは
 * 失われている。したがって `class Deps { fetchImpl() { return this.agent.fetch(…) } }` 形の
 * DI を使う呼び出し側は、**渡す前に自分で束ねること**（`resolveInjectedFetch(deps)` の
 * `receiver` へ `bind` する。`credential/json-schema/fetch-document.ts` が例）。合成した
 * リテラルを使うのは、`Object.prototype` 汚染を避けつつ「注入された値がグローバル `fetch`
 * そのものか」の判定を 1 か所（`resolveInjectedFetch`）に閉じるためである。init に `body` は
 * **載せない** — GET に body を付けると Node/undici とブラウザは `Request` 構築の時点で
 * `TypeError: Request with GET/HEAD method cannot have body.` を投げ、空文字でも例外になる
 * （`http/get-fetch.ts`）。
 *
 * **`fetchImpl` は呼び出し側が `nonObjectPrototypeProperty` で解決した値を渡すこと。**
 * ここは値しか受け取らないので、呼び出し側が `deps.fetchImpl` と素の鎖読みで取り出していると、
 * `Object.prototype.fetchImpl` の汚染値がそのまま「注入された fetch」として通る。
 *
 * @param url 取得先の HTTPS URL。
 * @param fetchImpl HTTP 呼び出しの差し替えシーム（テスト注入用）。省略時はグローバル `fetch`。
 * @param failure 失敗を呼び出し側のエラーコードへ正規化するファクトリ。
 * @param expectedOrigin 束縛する origin（`scheme://host[:port]`）。省略時は origin を縛らない。
 * @param bodyLimit 本文上限の切り詰めと実バイト数の計上（総量予算で縛る呼び出し側用。省略時は 1 MiB のみ）。
 * @returns プロトタイプを外した JSON 文書（object であることまで検証済み）。
 * @throws `failure(reason)` が返すエラー。
 */
export async function fetchJsonWithinLimits(
  url: string,
  fetchImpl: FetchLike | undefined,
  failure: JsonFetchFailure,
  expectedOrigin?: string,
  bodyLimit?: BodyLimitOptions,
): Promise<object> {
  // 呼び出し側の HTTPS 検査を前提にしつつ、忘れた新規呼び出し側が SSRF / 平文降格の入口に
  // ならないよう自衛でも確かめる。
  if (!isPublicHttpsUrl(url)) {
    throw failure('non_https_url');
  }
  // `fetchImpl` は常に own プロパティとして載せる（省略時も）。空リテラルを渡すと
  // `Object.prototype.fetchImpl` の汚染値を掴み、取得ごと攻撃者へ委譲される。
  const { doFetch, receiver } = resolveInjectedFetch({ fetchImpl });
  const controller = new AbortController();
  // 本文の読み出しまでを 1 つのタイムアウトで覆う（`clearTimeout` は本文読了後）。
  const timer = setTimeout(() => controller.abort(), JSON_FETCH_TIMEOUT_MS);
  // 読まずに失敗へ倒す経路でも本文を解放できるよう、`finally` から見える位置で宣言する。
  let response: Response | undefined;
  // 実際に辿った最終ホップの URL（`response.url` が空の DI 実装でも origin 束縛を最終 URL に課すため）。
  let finalUrl = url;
  try {
    try {
      // init に `body` を載せない。GET + body は Node/undici とブラウザで `Request` 構築の
      // 時点で TypeError になり（空文字でも例外）、実 fetch を使う本番経路が 1 度もネットワークへ
      // 到達しなくなる。Bun だけが許容するのでスタブ注入のテストでは表面化しない。
      // リダイレクトはホップごとに公開 HTTPS 宛へ縛って追従する（中間ホップへの GET も出さない）。
      ({ response, finalUrl } = await fetchFollowingPublicRedirectsWithFinalUrl(
        bindForPublicRedirects(doFetch, receiver),
        url,
        { method: 'GET', headers: { Accept: 'application/json' }, signal: controller.signal },
      ));
    } catch (error) {
      // 検査による拒否はネットワーク不達と区別する。URL を漏らさないため cause は握りつぶす。
      throw failure(
        error instanceof PublicRedirectRejection ? 'redirect_rejected' : 'fetch_failed',
      );
    }
    const rejection = finalUrlRejection(finalUrl, response, expectedOrigin);
    if (rejection !== undefined) {
      throw failure(rejection);
    }
    if (!response.ok) {
      throw failure('http_error');
    }
    // 「JSON に見える別物」を掴まないため Content-Type を必須にする。
    if (!isJsonContentType(response.headers.get('content-type'))) {
      throw failure('invalid_content_type');
    }
    // 自己申告の `content-length` で早期に落とし、実バイト数でも打ち切る。
    if (declaresOversizedBody(response, bodyLimit)) {
      throw failure('oversized_body');
    }
    let text: string | undefined;
    try {
      text = await readBodyWithinLimit(response, bodyLimit);
    } catch (error) {
      // 呼び出し側の `onBytes` が投げた `VericertsError` はそのまま通す。読み取ったバイト数を
      // 予算から引く用途で渡されるコールバックで、超過時は 3061 を投げる。これを握り潰して
      // `fetch_failed`（= 取得失敗）へ正規化すると、**予算超過が「取得に失敗した」に化ける**。
      // 取得失敗は `failSafePolicy` の同意コールバックと監査記録があれば FO-3 で通過できるため、
      // 予算の上限を超えた処理がそのまま続行してしまう。
      if (error instanceof VericertsError) throw error;
      // それ以外は本文読み出し中のネットワークエラー / abort。本文・URL は載せない。
      throw failure('fetch_failed');
    }
    if (text === undefined) {
      throw failure('oversized_body');
    }
    let parsed: unknown;
    try {
      parsed = parseJsonWithoutPrototype(text);
    } catch {
      // 応答本文は message にも context にも載せない。
      throw failure('invalid_json');
    }
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
      throw failure('invalid_metadata');
    }
    return parsed;
  } finally {
    clearTimeout(timer);
    // 本文を読まずに throw した経路が接続を掴んだまま残らないようにする（読了後は no-op）。
    discardBody(response);
  }
}
