/**
 * OID4VP `request_uri` 参照形式の Request Object（JAR / RFC 9101）取得。
 *
 * HAIP §5.1 の提示要求では、`request_uri` から署名付き Request Object を取得する。
 *
 * 参照形式の提示要求（`openid4vp://?client_id=…&request_uri=https://rp/req/<id>`）は、実パラメータを
 * クエリに載せず Verifier が署名した Request Object（コンパクト JWS）に入れる。Wallet はその JWS を
 * `request_uri` から **HTTP GET で取得**してはじめて DCQL 評価へ進める。本モジュールは
 * GET による取得、署名検証、`PresentationRequest` への正規化を行う。
 *
 * **なぜ取得を独立モジュールにするか。** `request_uri` は deep link / QR 由来 = **攻撃者が値を選べる
 * URL** であり、SDK にとっては SSRF と平文降格の入口である。その入口検査（公開 HTTPS URL 限定・リダイレクト先の
 * 検査・タイムアウト）を 1 か所へ閉じ込めて監査可能にする（`eudi/issuance/metadata.ts` が
 * Issuer Metadata 取得で同じ形を取るのと同じ理由）。解析側（`request.ts` の `parseJarRequest`）は
 * 同期の純粋関数のまま保ち、取得の有無で挙動が変わらないようにする。
 *
 * **署名検証は取得の直後・解析の前に行う**。取得した JWS は
 * `jar-signature.ts` の `verifyJarSignature` を通り、`x5c` の Trust Anchor 到達・JWS 署名・
 * `iss == client_id`・SubjectAltName == `client_id` == `response_uri` ドメインのすべてを満たした
 * ものだけが `parseJarRequest` へ渡る。本モジュールが課す HTTPS 強制・リダイレクト降格拒否と、
 * `parseJarRequest` が課す `response_uri` の HTTPS 検査・`client_id` オリジン一致検査は
 * **署名検証の代わりにはならない**（攻撃者は `client_id` と `response_uri` を自分のドメインで
 * 揃えればそれらを通過できる）ため、3 者はいずれも省略できない。
 *
 * スコープ外（別フェーズの責務）:
 * - `request_uri_method=post`（OpenID4VP §5.10）。本 SDK は GET のみを行う。
 * - VP Token 構築・`direct_post` 送信（`oid4vp.ts` / `oid4vp-submit.ts`）。
 * - OpenID Federation / ARF Trust Anchor の評価。`federationTrustAnchor` / `arfTrustAnchor` は
 *   `verifyJarSignature` へ転送し、OIDF / ARF による証明書の信頼判定を委譲する。
 *
 * セキュリティ上の注意:
 * - `request_uri` が HTTPS でなければ**取得せずに**拒否する。平文 HTTP で Request Object を受け取ると、
 *   中間者が `response_uri` / `nonce` / `dcql_query` を差し替えられ、VP Token の送信先を奪える。
 * - リダイレクトの各転送先を公開 HTTPS URL に限定し、応答の URL があればそれも確認する。
 * - タイムアウトは**本文読了まで**を 1 つの `AbortController` で覆う（`clearTimeout` は本文を読み終えて
 *   から行う）。ヘッダだけ先に返して本文を引き延ばす Verifier に無限に待たされないため。
 * - 本文には 1 MiB の上限を課す（`http/body-limit.ts`）。タイムアウトだけでは 10 秒ぶんの巨大な
 *   本文を確保でき、しかも署名検証は読み出しの**後**なので、モバイルウォレットでは未検証の
 *   Verifier 応答だけでメモリを枯渇させられる。
 * - 例外の `context` には固定の識別子だけを載せ、`request_uri`・レスポンス本文（JWT）・`cause` を
 *   一切含めない。
 */

import type { FetchLike } from '../../fetch-di.js';
import { resolveInjectedFetch } from '../../fetch-di.js';
import { declaresOversizedBody, discardBody, readBodyWithinLimit } from '../../http/body-limit.js';
import { isPublicHttpsUrl } from '../../http/public-https-url.js';
import {
  bindForPublicRedirects,
  fetchFollowingPublicRedirects,
} from '../../http/public-redirect-fetch.js';
import { isNonBlankString } from '../../prototype-safety/non-empty-string.js';
import type { PresentationRequest } from '../request.js';
import { parseJarRequest } from '../request.js';
import { jarFailure } from './jar-failure.js';
import type { JarTrustOptions } from './jar-signature.js';
import { requireJarTrustAnchors, verifyJarSignature } from './jar-signature.js';

/**
 * JAR 取得のタイムアウト（ミリ秒）。他の「攻撃者が影響し得る URL への GET」
 * （Issuer Metadata / JSON Schema 取得）と揃えて 10 秒。
 */
const JAR_FETCH_TIMEOUT_MS = 10_000;

/**
 * JAR の Content-Type（RFC 9101 §5.2）。**要求はするが応答の検査はしない**（後述）。
 */
const JAR_MEDIA_TYPE = 'application/oauth-authz-req+jwt';

/**
 * `fetchJAR` のオプション（取得シーム + JAR の署名検証材料）。
 *
 * 取得失敗も署名検証失敗も `OID4VP_REQUEST_PARSE_FAILED`（8030）へ正規化する（`jar-failure.ts`）。
 * 呼び出し側にとってはどちらも「この提示要求は成立しない」という 1 つの結末であり、
 * `request_uri` を取り直しても同じ Verifier の同じ要求は復旧しないためである。
 *
 * `JarTrustOptions` を継承するため **`trustAnchors` は必須**である。`fetchJAR` は参照形式だけを
 * 扱う低レベル API なので、署名検証を省ける呼び出しが型として存在しない状態にしておく
 * （直接形式も受ける `parsePresentationRequest` 側は、参照形式に分岐した時点で実行時に要求する）。
 *
 * @experimental 挙動・シグネチャが変わり得る（v1.0 で `@stable` 昇格予定）。
 */
export interface FetchJarOptions extends JarTrustOptions {
  /** HTTP 呼び出しの差し替えシーム（テスト注入用）。省略時はグローバル `fetch`。 */
  readonly fetchImpl?: FetchLike;
}

/**
 * `request_uri` から Request Object（JAR JWT）を取得し、`PresentationRequest` へ正規化する。
 *
 * 手順:
 * 0. 署名者を検証する Trust Anchor が設定されていなければ、取得前に拒否する。
 * 1. `requestURI` が空、または公開 HTTPS URL でなければ**取得せずに**拒否する（fetch は一切発生しない）。
 * 2. `GET <requestUri>`（`Accept: application/oauth-authz-req+jwt`）を 10 秒のタイムアウト付きで行う。
 * 3. リダイレクト先が公開 HTTPS URL でなければ拒否する。
 * 4. 非 2xx / 本文読み出し失敗 / 本文の上限（1 MiB）超過 / 空本文を拒否する。
 * 5. 取得した JWS の**署名を検証する**（`verifyJarSignature`）。
 * 6. 検証を通った JWS を `parseJarRequest` へ渡し、必須パラメータ検証・`response_uri` の HTTPS
 *    検査・`client_id` オリジン一致検査を通した `PresentationRequest` を返す。
 *
 * **応答の `Content-Type` は検査しない。** RFC 9101 §5.2 の `application/oauth-authz-req+jwt` を
 * `Accept` で要求はするが、現に稼働する Verifier は `application/jwt` や `text/plain` を返すものが
 * あり、媒体型で落とすと正当な要求を Wallet 側で拒否してしまう。媒体型が正しくても中身が JWS で
 * なければ `parseJarRequest` が `8030` で落とすため、検査を媒体型ではなく**中身**に置く。
 *
 * `fetchImpl` は必ず**引数**で受け取り、`doFetch.call(receiver, …)` の形で呼ぶ（横断
 * `fetch-di.ts`。裸呼び出しは prototype メソッド実装の `this` を壊す）。DI の解決元には
 * **呼び出し側の `options` をそのまま渡す**（中間の literal を作らない。`oid4vp-submit.ts` の
 * `postForm` と同じ形）。中間の literal に詰め替えると、`fetchImpl` を指定していない呼び出しで
 * そのリテラルが `Object.prototype` を継承した状態になり、汚染された `Object.prototype.fetchImpl`
 * を掴んで Verifier の Request Object ごと攻撃者の実装へ委譲される。`resolveInjectedFetch` は
 * `Object.prototype` 由来の値を採用しないが、レシーバも解決元と一致させておく必要がある。
 *
 * GET リクエストは本文を付けずに送る。
 *
 * @param requestURI Authorization Request の `request_uri`（HTTPS の絶対 URL）。
 * @param options Trust Anchor（必須）・deep link の `client_id`・Verifier の署名 alg 告知・
 *                失効集合・基準時刻と、HTTP 呼び出しの差し替えシーム。
 * @returns 正規化された `PresentationRequest`。
 * @throws 非 HTTPS / 通信失敗 / タイムアウト / 非 2xx / リダイレクト降格 / 本文の上限超過 / 空本文 /
 *         JWS 形式不正 / 署名検証失敗（Trust Anchor 未到達・署名不正・`iss != client_id` 等）/
 *         必須パラメータ欠落の場合（VericertsError、code `8030`）。
 */
export async function fetchJAR(
  requestURI: string,
  options: FetchJarOptions,
): Promise<PresentationRequest> {
  // Trust Anchor が無ければ取得結果を検証できない。検証できないものを取りに行かない
  // （`request_uri` は攻撃者が値を選べる URL であり、無駄な GET は存在確認の副作用になる）。
  requireJarTrustAnchors(options);
  if (!isNonBlankString(requestURI)) {
    throw jarFailure('missing_request_uri');
  }
  // Request Object を平文で受け取ると `response_uri` / `nonce` / `dcql_query` を差し替えられる。
  if (!isPublicHttpsUrl(requestURI)) {
    throw jarFailure('non_https_request_uri');
  }
  const { doFetch, receiver } = resolveInjectedFetch(options);
  const controller = new AbortController();
  // 本文の読み出しまでを 1 つのタイムアウトで覆う（`clearTimeout` は本文読了後）。
  const timer = setTimeout(() => controller.abort(), JAR_FETCH_TIMEOUT_MS);
  // 読まずに失敗へ倒す経路でも本文を解放できるよう、`finally` から見える位置で宣言する。
  let response: Response | undefined;
  try {
    try {
      // リダイレクトはホップごとに公開 HTTPS 宛へ縛って追従する。GET に body は載せない。
      response = await fetchFollowingPublicRedirects(
        bindForPublicRedirects(doFetch, receiver),
        requestURI,
        { method: 'GET', headers: { Accept: JAR_MEDIA_TYPE }, signal: controller.signal },
      );
    } catch {
      // ネットワークエラー / タイムアウト（abort）。URL を漏らさないため cause は握りつぶす。
      throw jarFailure('fetch_failed');
    }
    // リダイレクト先が HTTPS にとどまっていることを最終 URL のスキームで検証する。
    if (response.url.length > 0 && !isPublicHttpsUrl(response.url)) {
      throw jarFailure('insecure_redirect');
    }
    if (!response.ok) {
      throw jarFailure('http_error');
    }
    // 自己申告の `content-length` で早期に落とし、偽装された場合も実バイト数で打ち切る
    // （`request_uri` は QR 由来で攻撃者が選べる URL のため、上限なしの読み出しは OOM になる）。
    if (declaresOversizedBody(response)) {
      throw jarFailure('oversized_body');
    }
    let text: string | undefined;
    try {
      text = await readBodyWithinLimit(response);
    } catch {
      // 本文読み出し中のネットワークエラー / abort。本文・URL は載せない。
      throw jarFailure('fetch_failed');
    }
    if (text === undefined) {
      throw jarFailure('oversized_body');
    }
    if (!isNonBlankString(text)) {
      // 空本文を `parseJarRequest` に渡しても 8030 になるが、原因が読める reason を付けて落とす。
      throw jarFailure('empty_request_object');
    }
    const jarJwt = text.trim();
    // 解析より先に署名を検証する。順序が逆だと、署名が不正な Request Object の
    // `dcql_query` を解析した結果が（たとえ最終的に拒否されても）呼び出し側の分岐材料になり得る。
    await verifyJarSignature(jarJwt, options);
    // 必須パラメータ検証・`response_uri` の HTTPS / オリジン一致検査は `parseJarRequest` が
    // 直接形式と共通の規則で行う。
    return parseJarRequest(jarJwt);
  } finally {
    clearTimeout(timer);
    // 本文を読まずに throw した経路が接続を掴んだまま残らないようにする（読了後は no-op）。
    discardBody(response);
  }
}
