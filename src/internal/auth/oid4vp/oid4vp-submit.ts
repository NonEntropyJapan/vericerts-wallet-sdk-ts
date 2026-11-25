/**
 * OID4VP Authorization Response の送信（`direct_post` / `direct_post.jwt`）。
 *
 * VP Token の構成は `buildVPToken` が担う。
 *
 * 対応 response_mode:
 *
 * | `response_mode`    | POST 本文                                        | 秘匿性                          |
 * | ------------------ | ------------------------------------------------ | ------------------------------- |
 * | `direct_post`      | `vp_token` + `state`（+ `presentation_submission`）| 平文（TLS のみ）                |
 * | `direct_post.jwt`  | `response`（JWE Compact 1 個）                    | Verifier 公開鍵で end-to-end 暗号化 |
 *
 * `presentation_submission` の既定構築は `presentation-submission.ts`。
 *
 * `direct_post.jwt` では `vp_token` / `presentation_submission` / `state` を JWE ペイロードに収めて
 * 暗号化するため、フォーム本文には `response` のみを載せる。中間 CORS プロキシ・
 * アクセスログ・TLS 終端に平文 VP が残らないことが目的。
 *
 * セキュリティ上の注意:
 * - HTTP レスポンス本文は読み取らない（VP 検証エラー詳細など秘密を含み得るため）。失敗は
 *   `PRESENTATION_SUBMIT_FAILED`（8035）に正規化し `cause` も渡さない。
 * - 暗号化を要求されたのに暗号化できない場合、平文 `direct_post` にフォールバックしない
 *   （8036 で失敗させる方が安全側）。
 * - `response_uri` は `https` のみ許可する。平文 HTTP に
 *   VP Token を載せると TLS 保護なしで漏洩する。`did:web`（`method-web.ts`）や JSON Schema 取得
 *   （`json-schema/fetch-document.ts`）と同じく、loopback などの開発向け例外は設けない。
 * - **リダイレクトに追従しない**。送信先は `request.ts` が `client_id` と origin 一致を
 *   検証した `response_uri` に固定されるべきで、Verifier が返す 307/308 に追従すると同じ本文
 *   （VP Token）が任意のオリジンへ再送され、パース時のオリジン検査が完全に無効化される。
 */

import { ErrorCodes, VericertsError } from '../../errors.js';
import { resolveInjectedFetch } from '../../fetch-di.js';
import { discardBody } from '../../http/body-limit.js';
import { isPublicHttpsUrl } from '../../http/public-https-url.js';
import type { CorrelationContext } from '../../observability/correlation.js';
import { correlationHeaders, readCorrelationContext } from '../../observability/correlation.js';
import { buildEncryptedResponse, resolveResponseEncryption } from '../jwe/index.js';
import type { PresentationRequest } from '../request.js';
import { resolvePresentationSubmission } from './presentation-submission.js';

/** 平文の `direct_post` レスポンスモード。 */
export const RESPONSE_MODE_DIRECT_POST = 'direct_post' as const;
/** JWE 暗号化応答の `direct_post.jwt` レスポンスモード。 */
export const RESPONSE_MODE_DIRECT_POST_JWT = 'direct_post.jwt' as const;

/** 送信のタイムアウト（ミリ秒）。OID4VCI Token Request と同じ既定 30 秒。 */
const SUBMIT_TIMEOUT_MS = 30_000;

/** `response_uri` に要求するスキーム。 */
const HTTPS_PROTOCOL = 'https:';

/**
 * VP Token 送信の `fetch` 差し替えシーム。
 *
 * OID4VCI 側の `FetchLike`（`oid4vci/oid4vci.ts`）と別型なのは、本経路がリダイレクト
 * 不追従を成立させるために `redirect` を必ず渡すためである。注入側にも「3xx に追従してはならない」
 * ことを型で伝える意図があり、揺れではない。指定を無視した実装に備えて `assertNotRedirected` が
 * 最終 URL の origin を再検査する多層防御は従来どおり効く。
 */
export type SubmitFetchLike = (
  input: string,
  init: {
    method: string;
    headers: Record<string, string>;
    body: string;
    redirect: RequestRedirect;
    signal: AbortSignal;
  },
) => Promise<Response>;

/** `submitPresentation` の任意パラメータ。 */
export interface SubmitPresentationOptions {
  /**
   * HTTP 呼び出しの差し替えシーム。省略時はグローバル `fetch` を使う。
   * 解決規則は OID4VCI 経路と共有する（`resolveInjectedFetch`）。
   */
  readonly fetchImpl?: SubmitFetchLike;
  /**
   * PEx v2 Presentation Submission（`presentation_definition` 経路で提示する場合）。
   * DCQL 提示では省略する。
   */
  readonly presentationSubmission?: Readonly<Record<string, unknown>>;
  /**
   * Wallet が生成した `wallet_nonce`。`direct_post.jwt` で ECDH-ES の `apu`（PartyUInfo）を
   * `SHA-256(wallet_nonce)` として導出するために使う。未指定なら `apu` を省略する。
   */
  readonly walletNonce?: string;
  /**
   * 1 回のユーザー操作に紐づく相関 ID。指定すると `traceparent` /
   * `X-Request-Id` ヘッダで Verifier へ伝播する（`direct_post` / `direct_post.jwt` 共通）。
   * 同じ操作の OID4VCI 経路（`PARRequest` / `*TokenRequest` の `correlationContext`）と
   * **同じ値**を渡すこと。未指定ならヘッダ自体を出さない。
   *
   * 相関 ID はヘッダにのみ載せる。フォーム本文は VP Token（`direct_post`）ないし JWE
   * （`direct_post.jwt`）であり、観測用の値は含まない。
   */
  readonly correlationContext?: CorrelationContext;
}

/** `vp_token` パラメータの本文。複数クレデンシャルは JSON 配列文字列として送る。 */
function encodeVpTokenParam(vpToken: string | string[]): string {
  return Array.isArray(vpToken) ? JSON.stringify(vpToken) : vpToken;
}

/** 平文 `direct_post` のフォーム本文を組み立てる。 */
function buildDirectPostBody(
  request: PresentationRequest,
  vpToken: string | string[],
  options: SubmitPresentationOptions,
): URLSearchParams {
  const params = new URLSearchParams();
  params.set('vp_token', encodeVpTokenParam(vpToken));
  params.set('state', request.state);
  const presentationSubmission = resolvePresentationSubmission(request, vpToken, options);
  if (presentationSubmission !== undefined) {
    params.set('presentation_submission', JSON.stringify(presentationSubmission));
  }
  return params;
}

/**
 * `direct_post.jwt` のフォーム本文（`response=<JWE compact>`）を組み立てる。
 *
 * @throws 暗号化パラメータを解決できない場合（VericertsError、code `8036`）、
 *         JWE 構築に失敗した場合（VericertsError、code `8037`）。
 */
async function buildDirectPostJwtBody(
  request: PresentationRequest,
  vpToken: string | string[],
  options: SubmitPresentationOptions,
): Promise<URLSearchParams> {
  // `clientMetadata` は任意プロパティ。`request.clientMetadata` はプロトタイプ鎖を辿るため、
  // `Object.prototype.clientMetadata` が汚染された環境では **Verifier が `client_metadata` を
  // 告知していない要求でも汚染値が暗号化パラメータとして解決され、vp_token が攻撃者の鍵で
  // 暗号化されて送出される**。自身のプロパティに限って読み、未告知なら 8036 で失敗させる。
  const clientMetadata = Object.hasOwn(request, 'clientMetadata')
    ? request.clientMetadata
    : undefined;
  const encryption = resolveResponseEncryption(clientMetadata);
  const presentationSubmission = resolvePresentationSubmission(request, vpToken, options);
  const walletNonce = Object.hasOwn(options, 'walletNonce') ? options.walletNonce : undefined;
  const response = await buildEncryptedResponse(
    encryption,
    {
      vpToken,
      state: request.state,
      ...(presentationSubmission !== undefined ? { presentationSubmission } : {}),
    },
    request.nonce,
    walletNonce,
  );
  const params = new URLSearchParams();
  // `state` は JWE ペイロード内に含まれるため、フォーム本文には載せない。
  params.set('response', response);
  return params;
}

/** 送信失敗（8035）を組み立てる。`reason` は秘密を含まない固定識別子のみ。 */
function submitFailed(reason?: string): VericertsError {
  return new VericertsError(
    ErrorCodes.PRESENTATION_SUBMIT_FAILED,
    reason !== undefined ? { context: { reason } } : undefined,
  );
}

/**
 * `response_uri` が公開ホスト宛の https 絶対 URL であることを検証し、その origin を返す。
 *
 * `request.ts` のパース時検査を通っていない `PresentationRequest`（呼び出し側が手組みした場合や、
 * パース後に差し替えられた場合）でも平文 HTTP へ VP Token を送らないための多層防御。
 *
 * @throws 絶対 URL でない / スキームが `https` でない / 非公開ホスト宛の場合（VericertsError、code `8035`）。
 */
function assertSecureResponseUri(responseUri: string): string {
  let url: URL;
  try {
    url = new URL(responseUri);
  } catch {
    throw submitFailed('invalid_response_uri');
  }
  if (url.protocol !== HTTPS_PROTOCOL) {
    throw submitFailed('insecure_response_uri');
  }
  // Verifier（相手）が選ぶ URL へ VP Token を POST するため、ループバック / プライベート /
  // リンクローカル宛（SSRF）も拒否する。
  if (!isPublicHttpsUrl(responseUri)) {
    throw submitFailed('non_public_response_uri');
  }
  return url.origin;
}

/**
 * レスポンスがリダイレクトでないこと・最終 URL が `response_uri` の origin から動いていないことを
 * 検証する。
 *
 * `redirect: 'manual'` の返り方は実装差がある（ブラウザは `type='opaqueredirect'` / `status=0`、
 * Node・Bun は 3xx をそのまま返す）。いずれも「追従しなかった」ものとして失敗させ、VP Token を
 * 再送しない。加えて、注入された fetch 実装が `redirect` 指定を無視した場合に備え、最終 URL の
 * origin も再検査する（`json-schema/fetch-document.ts` と同じ多層防御）。
 *
 * @throws 3xx 応答 / 最終 URL の origin 不一致の場合（VericertsError、code `8035`）。
 */
function assertNotRedirected(response: Response, expectedOrigin: string): void {
  if (response.type === 'opaqueredirect' || (response.status >= 300 && response.status < 400)) {
    throw submitFailed('redirect_not_followed');
  }
  // 構築済み `Response`（テスト等）では `url` が空文字列になる。その場合は追加検査を行わない。
  if (response.url.length > 0 && finalOrigin(response.url) !== expectedOrigin) {
    throw submitFailed('response_uri_origin_changed');
  }
}

/** 最終 URL の origin を取り出す。パース不能なら `undefined`（＝不一致扱い）。 */
function finalOrigin(url: string): string | undefined {
  try {
    return new URL(url).origin;
  } catch {
    return undefined;
  }
}

/**
 * 組み立て済みフォーム本文を `response_uri` へ POST する。
 *
 * 非 https の `response_uri`・リダイレクト応答・非 2xx・ネットワーク失敗・タイムアウトはすべて
 * `PRESENTATION_SUBMIT_FAILED`（8035）へ正規化する（再試行可能。VP Token は再構築不要）。
 */
async function postForm(
  responseUri: string,
  params: URLSearchParams,
  options: SubmitPresentationOptions,
): Promise<void> {
  const expectedOrigin = assertSecureResponseUri(responseUri);
  // 解決規則（`Object.prototype` 由来と非関数を未注入に倒し、取り出し元をレシーバとして呼ぶ）は
  // OID4VCI 経路と共有する。戻り値の `FetchLike` は `redirect` を持たないため、本経路の
  // `SubmitFetchLike` へ読み替える（実体は同じ関数で、渡す init が 1 フィールド広いだけ）。
  const { doFetch, receiver } = resolveInjectedFetch(options);
  const submitFetch = doFetch as unknown as SubmitFetchLike;
  // 相関 ID も純データなので own 限定で 1 回だけ読む。形が壊れていれば未指定として扱い、
  // 送信自体は止めない（観測用の補助情報の不備で VP 提示を失敗させない）。
  const correlationContext = readCorrelationContext(options);
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), SUBMIT_TIMEOUT_MS);
  // 読まずに失敗へ倒す経路でも本文を解放できるよう、`finally` から見える位置で宣言する。
  let response: Response | undefined;
  try {
    response = await submitFetch.call(receiver, responseUri, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        // 相関 ID を指定したときだけヘッダを送る。
        ...correlationHeaders(correlationContext),
      },
      body: params.toString(),
      // 3xx に追従して同じ本文（VP Token）を別オリジンへ再送しない。
      redirect: 'manual',
      signal: controller.signal,
    });
  } catch {
    // ネットワークエラー / タイムアウト（abort）。詳細は秘密を含み得るため正規化する。
    throw submitFailed();
  } finally {
    clearTimeout(timer);
    // この経路は成功・失敗のどちらでも本文を読まない（読むのは呼び出し側の責務外）。
    // 読まないなら明示的に解放する。以降の検査はヘッダ／ステータスしか見ないため影響しない。
    discardBody(response);
  }
  assertNotRedirected(response, expectedOrigin);
  // 非 2xx はすべて送信失敗扱い。レスポンス本文（VP 検証エラー詳細等）は読み取らず正規化する。
  if (!response.ok) {
    throw submitFailed();
  }
}

/**
 * VP Token を Verifier へ送信する。
 *
 * 送信形式は Authorization Request の `response_mode` から決定する。呼び出し側が平文 / 暗号化を
 * 選ぶ余地は無く、Verifier が `direct_post.jwt` を要求していれば必ず JWE 暗号化して送る。
 *
 * - `direct_post`: `vp_token` + `state`（+ 任意の `presentation_submission`）を
 *   `application/x-www-form-urlencoded` で POST する。
 * - `direct_post.jwt`: `{ vp_token, presentation_submission?, state }` を Verifier の
 *   `client_metadata` が示す公開鍵で JWE 暗号化し、`response` パラメータ 1 個で POST する。
 *
 * 検証者が返す `redirect_uri` 等のレスポンス本文の解釈は呼び出し側の責務とする。HTTP リダイレクト
 * には追従せず、3xx 応答は送信失敗として扱う。
 *
 * @param request パース済み OID4VP Authorization Request（`response_uri` / `state` / `response_mode` /
 *                `client_metadata` を含む）。
 * @param vpToken `buildVPToken` が構成した VP Token（文字列 / 文字列配列）。
 * @param options `presentation_submission` / `wallet_nonce` / `correlationContext`（いずれも任意）。
 * @throws 未対応 response_mode / 非 https の `response_uri` / リダイレクト応答 / HTTP エラー /
 *         ネットワーク失敗時（VericertsError、code `8035`）、
 *         応答暗号化パラメータを解決できない場合（`8036`）、JWE 構築に失敗した場合（`8037`）。
 */
export async function submitPresentation(
  request: PresentationRequest,
  vpToken: string | string[],
  options: SubmitPresentationOptions = {},
): Promise<void> {
  if (request.responseMode === RESPONSE_MODE_DIRECT_POST) {
    return postForm(request.responseUri, buildDirectPostBody(request, vpToken, options), options);
  }
  if (request.responseMode === RESPONSE_MODE_DIRECT_POST_JWT) {
    return postForm(
      request.responseUri,
      await buildDirectPostJwtBody(request, vpToken, options),
      options,
    );
  }
  throw new VericertsError(ErrorCodes.PRESENTATION_SUBMIT_FAILED, {
    context: { reason: 'unsupported_response_mode' },
  });
}
