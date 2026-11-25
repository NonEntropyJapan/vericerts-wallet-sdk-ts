/**
 * OID4VCI Token Endpoint の HTTP 送信とレスポンス正規化（Wallet 側）。
 *
 * 本モジュールは `oid4vci-token.ts` のグラント別の組み立て（`requestTokenPreAuthorized` /
 * `requestTokenAuthorizationCode`）から、両者が共有する「Token Endpoint へ POST し、応答 JSON を
 * `TokenResponse` へ正規化する」部分だけを切り出したものである。切り出しの契機は
 * `.linterly.yml` の 1 ファイル 300 行上限だが、境界は行数ではなく責務で引いている
 * （グラント固有のパラメータ検査・組み立ては呼び出し側、ワイヤ I/O と応答検証は本モジュール）。
 *
 * エラー方針（8010 TOKEN_REQUEST_FAILED）:
 * - HTTP 非 2xx（OAuth エラー JSON `{ error, error_description }` を含む invalid_grant /
 *   invalid_request 等）、ネットワーク失敗・タイムアウト、レスポンス JSON 不正・
 *   必須フィールド欠落はすべて `TOKEN_REQUEST_FAILED`（8010、再試行不可）に正規化する。
 *   いずれも pre-authorized_code / 認可コードの再取得が必要なため再試行で解決しない。
 *
 * セキュリティ上の注意:
 * - 例外メッセージや `context` に pre-authorized_code・tx_code（PIN）・認可コード・
 *   code_verifier・client_assertion・DPoP proof・access_token・c_nonce 等の秘密を一切含めない。
 * - リクエストパラメータ・レスポンス本文に秘密が含まれ得るため、送信失敗・JSON parse 失敗時に
 *   `cause` を渡さず正規化する。
 */

import { ErrorCodes, VericertsError } from '../../../errors.js';
import { resolveInjectedFetch } from '../../../fetch-di.js';
import { discardBody, readBodyWithinLimit } from '../../../http/body-limit.js';
import { isPublicHttpsUrl, isRedirectedResponse } from '../../../http/public-https-url.js';
import type { CorrelationContext } from '../../../observability/correlation.js';
import { correlationHeaders } from '../../../observability/correlation.js';
import { MetricNames, type Metrics } from '../../../observability/metrics.js';
import { safeEmit } from '../../../observability/safe-emit.js';
import { isNonEmptyString, toFiniteNumber } from '../../../prototype-safety/non-empty-string.js';
import { ownProperty } from '../../../prototype-safety/own-property.js';
import { parseJsonWithoutPrototype } from '../../../prototype-safety/parse-json.js';
import type { DpopProof } from '../../dpop/dpop-common.js';
import { type DpopProofRebuilder, sendWithDpopNonceRetry } from '../dpop-nonce/index.js';

/** `postTokenRequest` のグラント種別（メトリクスの `flow` ラベル）。 */
export type TokenGrantFlow = 'pre-auth' | 'auth-code';

/** Token Request のタイムアウト（ミリ秒）。did:ipid Gateway と同じ既定 30 秒。 */
const TOKEN_REQUEST_TIMEOUT_MS = 30_000;

/**
 * Token Endpoint の応答。OAuth の snake_case フィールドを camelCase へ写す。
 */
export interface TokenResponse {
  /** 発行された access_token。 */
  readonly accessToken: string;
  /** トークン種別。OID4VCI では `Bearer`。 */
  readonly tokenType: string;
  /**
   * access_token の有効期間（秒）。任意（RFC 6749 §5.1 で RECOMMENDED。OID4VCI 1.0 も必須化しない）。
   * 応答が省略した場合は `undefined`。存在する場合は有限の非負数に限る。
   */
  readonly expiresIn?: number;
  /**
   * 旧 Draft 形式の Token Response が運ぶ `c_nonce`（JWT Proof の `nonce` 用）。任意。
   * OID4VCI 1.0 Final の Token Response には無く、`nonce_endpoint` から取得する（§6.2 / §7）。
   */
  readonly cNonce?: string;
  /** 旧 Draft 形式の `c_nonce_expires_in`（秒）。任意。 */
  readonly cNonceExpiresIn?: number;
}

/**
 * Token Endpoint のレスポンス JSON を `TokenResponse` にマッピング・検証する。
 *
 * 必須フィールド（access_token / token_type）の欠落・型不正は
 * `TOKEN_REQUEST_FAILED`（8010）に正規化する。`expires_in`（RFC 6749 §5.1 で RECOMMENDED）・
 * `c_nonce` / `c_nonce_expires_in`（OID4VCI 1.0 Final の Token Response には無い）は任意で、
 * 存在する場合だけ型を検査し（`expires_in` は有限の非負数）、不正なら同コードで拒否する。全メンバとも
 * own 限定で読むため、`Object.prototype` 汚染下でも欠落した応答は欠落として扱われる
 * （必須メンバは 8010 へ倒れ、任意メンバは採用されない。fail-closed）。
 *
 * `postTokenRequest` は `parseJsonWithoutPrototype` で本文を読み、プロトタイプを除去する。
 * 直接呼び出しでも AS が応答に含めた値だけを採用するため、各メンバは自身のプロパティに限って読む。
 *
 * パース境界を通らない本文に対する本層の検証のため、`postTokenRequest` 経由でない直接呼び出しを
 * `__tests__/token/oid4vci-token-http.pollution.test.ts` から行えるよう export している。
 */
export function parseTokenResponse(body: unknown): TokenResponse {
  if (typeof body !== 'object' || body === null || Array.isArray(body)) {
    throw new VericertsError(ErrorCodes.TOKEN_REQUEST_FAILED);
  }
  const accessTokenValue = ownProperty<unknown>(body, 'access_token');
  const accessToken = isNonEmptyString(accessTokenValue) ? accessTokenValue : null;
  const tokenTypeValue = ownProperty<unknown>(body, 'token_type');
  const tokenType = isNonEmptyString(tokenTypeValue) ? tokenTypeValue : null;
  const expiresInValue = ownProperty<unknown>(body, 'expires_in');
  const expiresIn = toFiniteNumber(expiresInValue) ?? undefined;
  const cNonceValue = ownProperty<unknown>(body, 'c_nonce');
  const cNonceExpiresInValue = ownProperty<unknown>(body, 'c_nonce_expires_in');
  const cNonce = isNonEmptyString(cNonceValue) ? cNonceValue : undefined;
  const cNonceExpiresIn = toFiniteNumber(cNonceExpiresInValue) ?? undefined;
  if (
    accessToken === null ||
    tokenType === null ||
    (expiresInValue !== undefined && (expiresIn === undefined || expiresIn < 0)) ||
    (cNonceValue !== undefined && cNonce === undefined) ||
    (cNonceExpiresInValue !== undefined && cNonceExpiresIn === undefined)
  ) {
    throw new VericertsError(ErrorCodes.TOKEN_REQUEST_FAILED);
  }
  return {
    accessToken,
    tokenType,
    ...(expiresIn === undefined ? {} : { expiresIn }),
    ...(cNonce === undefined ? {} : { cNonce }),
    ...(cNonceExpiresIn === undefined ? {} : { cNonceExpiresIn }),
  };
}

/**
 * Token Endpoint へ `application/x-www-form-urlencoded` で POST し、レスポンスを
 * `TokenResponse` にマッピングする共通処理。
 *
 * HTTP 非 2xx（OAuth エラー JSON を含む）・ネットワーク失敗・タイムアウト・
 * レスポンス不正はすべて `TOKEN_REQUEST_FAILED`（8010）に正規化する。本文・パラメータには
 * 秘密が含まれ得るため `cause` を渡さない。
 *
 * @param tokenEndpoint Issuer / AS の Token Endpoint URL。
 * @param params 送信する form パラメータ。
 * @param dpop 任意の DPoP proof（RFC 9449 §4.2）。指定時のみ `DPoP` ヘッダに載せる。
 *             呼び出し側が非空であることを検査済みであること。
 * @param fetchSource `fetchImpl` を読み取る DI 元（グラント別の Token Request オブジェクト）。
 *                    省略時はグローバル `fetch` を使う。
 * @param observability `vericerts_oid4vci_token_duration_seconds` の
 *                       記録先。呼び出し側（`requestTokenPreAuthorized` / `requestTokenAuthorizationCode`）
 *                       がグラント種別を`flow`として渡す。未指定なら記録しない。
 * @param correlationContext 相関 ID。指定時のみ `traceparent` /
 *                           `X-Request-Id`（+ `tracestate`）を載せる。呼び出し側が形を検証済みで
 *                           あること（`readCorrelationContext`）。
 * @param rebuildDpop `use_dpop_nonce` チャレンジ（RFC 9449 §8）を受けたときに nonce 付き proof を作り直す関数。
 *                    `dpop` 指定時のみ有効。再送は 1 回だけ（`dpop-nonce/index.ts`）。
 */
export async function postTokenRequest(
  tokenEndpoint: string,
  params: URLSearchParams,
  dpop?: DpopProof,
  fetchSource?: object,
  observability?: { readonly metrics: Metrics; readonly flow: TokenGrantFlow },
  correlationContext?: CorrelationContext,
  rebuildDpop?: DpopProofRebuilder,
): Promise<TokenResponse> {
  if (observability === undefined) {
    return postTokenRequestImpl(
      tokenEndpoint,
      params,
      dpop,
      fetchSource,
      correlationContext,
      rebuildDpop,
    );
  }
  const startedAt = Date.now();
  try {
    return await postTokenRequestImpl(
      tokenEndpoint,
      params,
      dpop,
      fetchSource,
      correlationContext,
      rebuildDpop,
    );
  } finally {
    safeEmit(() =>
      observability.metrics
        .histogram(MetricNames.OID4VCI_TOKEN_DURATION_SECONDS, { flow: observability.flow })
        .observe((Date.now() - startedAt) / 1000),
    );
  }
}

/** `postTokenRequest` の送信本体（計装を挟まない素の経路）。 */
async function postTokenRequestImpl(
  tokenEndpoint: string,
  params: URLSearchParams,
  dpop?: DpopProof,
  fetchSource?: object,
  correlationContext?: CorrelationContext,
  rebuildDpop?: DpopProofRebuilder,
): Promise<TokenResponse> {
  // pre-authorized_code / tx_code / 認可コード / code_verifier / client_assertion を載せた本文を
  // 平文・内部ネットワーク・ローカルホスト宛へ送らない（SSRF 防止。Credential Endpoint / PAR /
  // Nonce Endpoint と同じ検査を Token Endpoint にも課す）。送信前に落とすため fetch は呼ばれない。
  if (!isPublicHttpsUrl(tokenEndpoint)) {
    throw new VericertsError(ErrorCodes.TOKEN_REQUEST_FAILED);
  }
  // DI シームは Credential Endpoint 経路（`requestCredential`）/ PAR 経路と同じ解決規則を共有する
  // （`Object.prototype` 由来と非関数を未注入に倒し、取り出し元をレシーバとして呼ぶ）。
  const { doFetch, receiver } = resolveInjectedFetch(fetchSource ?? {});
  const controller = new AbortController();
  // 本文の読み出しまでを 1 つのタイムアウトで覆う（`clearTimeout` は本文読了後）。ヘッダだけ先に
  // 返して本文を引き延ばす AS に無限に待たないため（`internal/http/fetch-json.ts` の不変条件）。
  const timer = setTimeout(() => controller.abort(), TOKEN_REQUEST_TIMEOUT_MS);
  // 読まずに失敗へ倒す経路でも本文を解放できるよう、`finally` から見える位置で宣言する。
  let response: Response | undefined;
  try {
    try {
      // `DPoP-Nonce` + `use_dpop_nonce`（RFC 9449 §8）を受けたら nonce 付き proof で 1 回だけ再送する。
      response = await sendWithDpopNonceRetry(
        (proof) =>
          doFetch.call(receiver, tokenEndpoint, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/x-www-form-urlencoded',
              Accept: 'application/json',
              // RFC 9449 §5: DPoP proof は body ではなく `DPoP` ヘッダで送る。未指定時はヘッダ自体を出さない
              // （空ヘッダを送ると AS が DPoP 利用の意図ありと解釈して形式不正で落としうる）。
              ...(proof === undefined ? {} : { DPoP: proof }),
              // 相関 ID を指定したときだけヘッダを送る。
              ...correlationHeaders(correlationContext),
            },
            body: params.toString(),
            // 3xx に追従して秘密を含む本文を別ホストへ再送しない。
            redirect: 'manual',
            signal: controller.signal,
          }),
        dpop,
        rebuildDpop,
      );
    } catch {
      // ネットワークエラー / タイムアウト（abort）。詳細は秘密を含み得るため正規化する。
      throw new VericertsError(ErrorCodes.TOKEN_REQUEST_FAILED);
    }
    if (isRedirectedResponse(response)) {
      throw new VericertsError(ErrorCodes.TOKEN_REQUEST_FAILED);
    }
    // 非 2xx（invalid_grant / invalid_request / authorization_pending 等）はすべて失敗扱い。
    // OAuth エラー本文は読み取らず正規化する（本文に秘密が含まれ得る）。
    if (!response.ok) {
      throw new VericertsError(ErrorCodes.TOKEN_REQUEST_FAILED);
    }
    let body: unknown;
    try {
      // 本文も上限（`MAX_DOCUMENT_BYTES` = 1 MiB）の内側で読む。巨大応答でメモリを枯渇させない。
      const text = await readBodyWithinLimit(response);
      if (text === undefined) {
        throw new VericertsError(ErrorCodes.TOKEN_REQUEST_FAILED);
      }
      // 応答データに継承プロパティが混じらないように読み取る。
      body = parseJsonWithoutPrototype(text);
    } catch {
      // 本文読み出し中のネットワークエラー / abort / 上限超過 / パース失敗。
      throw new VericertsError(ErrorCodes.TOKEN_REQUEST_FAILED);
    }
    return parseTokenResponse(body);
  } finally {
    clearTimeout(timer);
    // 本文を読まずに throw した経路が接続を掴んだまま残らないようにする（読了後は no-op）。
    discardBody(response);
  }
}
