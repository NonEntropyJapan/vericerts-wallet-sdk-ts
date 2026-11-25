/**
 * well-known Metadata 文書の取得（OID4VCI 向けの入口）。
 *
 * OID4VCI の受領フローは 2 つの well-known 文書を引く:
 *
 * - `/.well-known/openid-credential-issuer`（Issuer Metadata。`eudi/issuance/metadata.ts`）
 * - `/.well-known/oauth-authorization-server`（AS Metadata、RFC 8414。`oid4vci/oid4vci-as-metadata.ts`）
 *
 * どちらも「**Credential Offer 由来 = 攻撃者が影響し得る URL** への HTTP GET」という同一の
 * 攻撃面を持ち、必要な入口検査も同一である。**その検査を 2 か所に書き写すと片方だけが
 * 更新されて弱くなる**ため、取得と入口検査は横断プリミティブ `internal/http/fetch-json.ts` が
 * 1 か所で持ち、本モジュールは「発行者識別子 + well-known パス → URL」の組み立てと HTTPS 検査
 * だけを足す。同じ取得本体は Issuer 由来のスキーマ文書取得
 * （`credential/json-schema/fetch-document.ts`）も共有する。
 *
 * 取得元の識別子と well-known パスから URL を組み立てない経路（JWT VC Issuer Metadata の
 * well-known は host と path の**あいだ**へ差し込む形で、単純連結では作れない。同 Metadata の
 * `jwks_uri` に至っては組み立て自体が無い）のために、URL を直接渡す入口
 * {@link fetchJsonDocument} も置く。
 *
 * セキュリティ上の注意:
 * - HTTPS 以外は**取得せずに**拒否する（fetch は 1 度も発生しない。SSRF / 平文降格の防止）。
 * - リダイレクト後も HTTPS にとどまることを最終 URL で確認する。取得元の origin を縛る経路
 *   （`jwks_uri` など）は、**リダイレクト後の最終 URL の origin**まで突き合わせる。取得前の URL
 *   だけを検査すると、同一 origin の URL が別 origin へ 302 した先をそのまま信じることになり、
 *   origin を縛った意味が消える（内部ホストへの SSRF 踏み台にもなる）。
 * - 本文検査・タイムアウト・パースの規則は `internal/http/fetch-json.ts` の docblock を参照。
 * - 例外の `context` には固定の識別子だけを載せ、URL・レスポンス本文・`cause` を一切含めない。
 *   失敗コードの選択は呼び出し側が渡す `failure` に委ねる（経路ごとに正規化先が違う）。
 */

import type { VericertsError } from '../../errors.js';
import type { FetchLike } from '../../fetch-di.js';
import { fetchJsonWithinLimits } from '../../http/fetch-json.js';
import { isPublicHttpsUrl } from '../../http/public-https-url.js';
import { trimTrailingSlashes } from '../../primitives/trim-trailing-slashes.js';

/**
 * well-known JSON 取得の失敗理由を呼び出し側のエラーコードへ正規化するファクトリ。
 * `vericerts-wallet-sdk/common` の公開型。pre-1.0 は entry 単位で experimental と扱う。
 */
export type WellKnownJsonFailure = (reason: string) => VericertsError;

/**
 * 発行元識別子と well-known パスから取得 URL を組み立てる。
 *
 * 末尾スラッシュを除去してから連結する（`https://issuer.example/` をそのまま連結すると
 * `//.well-known/...` になり、発行者によっては 404 になる）。
 */
function buildWellKnownUrl(issuer: string, wellKnownPath: string): string {
  return `${trimTrailingSlashes(issuer)}${wellKnownPath}`;
}

/**
 * well-known Metadata 文書を取得し、JSON オブジェクトとして返す。
 *
 * `issuer` が HTTPS でなければ**取得せずに**拒否する（`reason: 'non_https_issuer'`）。以降の手順と
 * 失敗理由は `internal/http/fetch-json.ts` の {@link fetchJsonWithinLimits} に従う。
 *
 * @param issuer 取得元の識別子（HTTPS の絶対 URL。末尾スラッシュは除去される）。
 * @param wellKnownPath `/.well-known/...` から始まるパス。
 * @param fetchImpl HTTP 呼び出しの差し替えシーム（テスト注入用）。省略時はグローバル `fetch`。
 * @param failure 失敗を呼び出し側のエラーコードへ正規化するファクトリ。
 * @param expectedOrigin 束縛する origin（`scheme://host[:port]`）。省略時は origin を縛らない。
 *                       取得元の origin が信頼の起点そのものである経路（JWT VC Issuer Metadata。
 *                       認証したのは `iss` の origin の TLS 証明書を持つホストだけ）では必ず渡す
 *                       — 渡さないと well-known が別 origin（内部ホストを含む）へ 302 した先に
 *                       追随し、その束縛が metadata 側で丸ごと迂回される。
 * @returns プロトタイプを外した Metadata 文書（オブジェクトであることまで検証済み）。
 * @throws `failure(reason)` が返す `VericertsError`。
 */
export async function fetchWellKnownJson(
  issuer: string,
  wellKnownPath: string,
  fetchImpl: FetchLike | undefined,
  failure: WellKnownJsonFailure,
  expectedOrigin?: string,
): Promise<object> {
  if (!isPublicHttpsUrl(issuer)) {
    throw failure('non_https_issuer');
  }
  return fetchJsonDocument(
    buildWellKnownUrl(issuer, wellKnownPath),
    fetchImpl,
    failure,
    expectedOrigin,
  );
}

/**
 * 組み立て済みの HTTPS URL から JSON 文書を取得する（{@link fetchWellKnownJson} のトランスポート）。
 *
 * well-known パスの差し込み規則が経路ごとに違う取得元（JWT VC Issuer Metadata とその `jwks_uri`）
 * のための入口である。HTTPS 検査は {@link fetchJsonWithinLimits} が自衛で行うため、
 * 忘れた呼び出し側でも `reason: 'non_https_url'` で落ちる。
 *
 * `credential/json-schema/fetch-document.ts` にあった**同名の別関数**（`ErrorCode` を受け取り
 * `Record<string, unknown>` を返す）は `fetchSchemaJson` へ改名した。同じ名前が 2 つあると
 * import 側でどちらを指しているか読み取れない（`fetchSchemaDocument` は
 * `credential/sdjwt/type-metadata/fetch.ts` の**さらに別の**既存関数なので、改名先として
 * 選べない）。取得本体は両者とも `internal/http/fetch-json.ts` を共有する。
 *
 * @param url 取得先の HTTPS URL。
 * @param fetchImpl HTTP 呼び出しの差し替えシーム（テスト注入用）。省略時はグローバル `fetch`。
 * @param failure 失敗を呼び出し側のエラーコードへ正規化するファクトリ。
 * @param expectedOrigin 束縛する origin（`scheme://host[:port]`）。省略時は origin を縛らない。
 * @returns プロトタイプを外した JSON 文書（オブジェクトであることまで検証済み）。
 * @throws `failure(reason)` が返す `VericertsError`。
 */
export function fetchJsonDocument(
  url: string,
  fetchImpl: FetchLike | undefined,
  failure: WellKnownJsonFailure,
  expectedOrigin?: string,
): Promise<object> {
  // `failure` は `(reason: string) => VericertsError` なので、引数の反変性で
  // `JsonFetchFailure`（`(reason: JsonFetchReason) => Error`）にそのまま代入できる。
  // 恒等ラッパーで包み直す必要はない。
  return fetchJsonWithinLimits(url, fetchImpl, failure, expectedOrigin);
}

/**
 * 発行元識別子と well-known パスから、RFC 8414 §3.1 の**挿入形**の取得 URL を組み立てる。
 *
 * 識別子が path 成分を持つとき、well-known 文字列を host と path の**あいだ**へ挿入する
 * （`https://idp.example.com/realms/acme` → `https://idp.example.com/.well-known/oauth-authorization-server/realms/acme`）。
 * path が無い（`/` のみ）識別子は末尾連結形と同じになる。識別子の query / fragment は
 * RFC 8414 §2 が持たせないと定める部分なので URL へ引き継がない。
 */
function buildInsertedWellKnownUrl(issuer: string, wellKnownPath: string): string {
  const { origin, pathname } = new URL(issuer);
  return `${origin}${wellKnownPath}${trimTrailingSlashes(pathname)}`;
}

/**
 * well-known Metadata 文書を RFC 8414 §3.1 の**挿入形**で取得し、JSON オブジェクトとして返す。
 *
 * AS Metadata（`/.well-known/oauth-authorization-server`）用。OID4VCI §11.2.2 が追記形と定める
 * Issuer Metadata（`/.well-known/openid-credential-issuer`）は {@link fetchWellKnownJson}（追記形）を使う。
 * 入口検査・失敗理由は {@link fetchWellKnownJson} と同一（`non_https_issuer` 等）。
 *
 * @param issuer 取得元の識別子（HTTPS の絶対 URL。path 成分を持ってよい）。
 * @param wellKnownPath `/.well-known/...` から始まるパス。
 * @param fetchImpl HTTP 呼び出しの差し替えシーム（テスト注入用）。省略時はグローバル `fetch`。
 * @param failure 失敗を呼び出し側のエラーコードへ正規化するファクトリ。
 * @returns プロトタイプを外した Metadata 文書（オブジェクトであることまで検証済み）。
 * @throws `failure(reason)` が返す `VericertsError`。
 */
export async function fetchInsertedWellKnownJson(
  issuer: string,
  wellKnownPath: string,
  fetchImpl: FetchLike | undefined,
  failure: WellKnownJsonFailure,
): Promise<object> {
  if (!isPublicHttpsUrl(issuer)) {
    throw failure('non_https_issuer');
  }
  return fetchJsonDocument(buildInsertedWellKnownUrl(issuer, wellKnownPath), fetchImpl, failure);
}
