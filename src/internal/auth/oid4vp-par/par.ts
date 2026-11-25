/**
 * OID4VP 経路の Pushed Authorization Request（PAR, RFC 9126）クライアント。
 *
 * Wallet が提示要求を事前登録するため、Verifier の PAR エンドポイントへ送信し、`request_uri` を受け取る。
 * 得られた URI は `fetchJAR` / `parsePresentationRequest` の参照形式で使える。
 * 呼び出し側が JAR を検証し、`nonce` / `state` が送信時の値と一致することを確認する。
 *
 * PKCE（S256）・CSRF 防止用の `state`・HTTPS・クライアントアサーションの組・DPoP ヘッダの扱いは
 * OID4VCI の PAR と共通（RFC 9126 / RFC 7521 / RFC 9449）。提示では `response_type=vp_token` とし、
 * Wallet が生成した `nonce` を必須とする。提示応答は `response_uri` への `direct_post` で返るため、
 * 発行時の `scope` / `authorization_details` / `redirect_uri` / `authorization_endpoint` は使用しない。
 *
 * HTTP・ネットワーク・応答の解析・入力検証の失敗は `OID4VP_PAR_REQUEST_FAILED`（8031、再試行可）で返す。
 * 例外メッセージや `context` に client_assertion・code_challenge・request_uri・nonce・state を含めない。
 * `client_assertion` を平文 body で送るため、HTTPS 以外のエンドポイントは拒否する。
 */

import { ErrorCodes, VericertsError } from '../../errors.js';
import type { FetchLike } from '../../fetch-di.js';
import { resolveInjectedFetch } from '../../fetch-di.js';
import { discardBody, readBodyWithinLimit } from '../../http/body-limit.js';
import { isPublicHttpsUrl, isRedirectedResponse } from '../../http/public-https-url.js';
import type { CorrelationContext } from '../../observability/correlation.js';
import { correlationHeaders, readCorrelationContext } from '../../observability/correlation.js';
import { isNonBlankString } from '../../prototype-safety/non-empty-string.js';
import { ownProperty } from '../../prototype-safety/own-property.js';
import { parseJsonWithoutPrototype } from '../../prototype-safety/parse-json.js';
import type { DpopProof } from '../dpop/dpop-common.js';
import { CODE_CHALLENGE_METHOD_S256, RESPONSE_TYPE_VP_TOKEN } from './params.js';
import { parseOID4VPPARResponse } from './response.js';

/** PAR Request のタイムアウト（ミリ秒）。OID4VCI 経路と揃えて 30 秒。 */
const PAR_REQUEST_TIMEOUT_MS = 30_000;

/**
 * OID4VP PAR エンドポイント（Verifier）へ push する認可パラメータ。
 *
 * ワイヤパラメータ名をそのまま写すフィールドは snake_case、`fetchImpl` / `correlationContext` の
 * ような DI seam・観測用の非ワイヤフィールドは camelCase。
 *
 * @experimental 公開直後は挙動・シグネチャが変わり得る（v1.0 で `@stable` 昇格予定）。
 */
export interface OID4VPPARRequest {
  /** Verifier の PAR エンドポイント（HTTPS 必須）。 */
  readonly par_endpoint: string;
  /**
   * Wallet の client_id（Verifier にあらかじめ登録済みのもの）。
   *
   * 提示要求内の `client_id` は Verifier 自身を表す。
   * 本フィールドは RFC 9126 の PAR エンドポイントへ要求する側（＝ Wallet）を識別するための
   * client_id で、Verifier が JAR を組み立てて返す際の宛先解決に使う。
   */
  readonly client_id: string;
  /** PKCE code_challenge（`BASE64URL(SHA256(code_verifier))`）。 */
  readonly code_challenge: string;
  /**
   * CSRF 防止 state（`crypto.getRandomValues` 由来 128-bit 以上）。
   *
   * Verifier から返る JAR に含まれる `state` と完全一致することを呼び出し側が
   * 確認すること（一致確認自体は本関数のスコープ外）。
   */
  readonly state: string;
  /**
   * OID4VP の必須パラメータ `nonce`。
   *
   * Verifier-initiated フローでは Verifier が生成するが、本経路は Wallet が Verifier へ
   * 先に押すため、生成は呼び出し側の責務とする（本 SDK は乱数生成を新設しない）。Verifier が
   * 返す JAR の `nonce` と一致することの確認は呼び出し側が行う。
   */
  readonly nonce: string;
  /**
   * client_assertion_type（RFC 7521 §4.2 が `client_assertion` 使用時に REQUIRED と定める）。
   * SDK は既定値を持たない。
   */
  readonly client_assertion_type?: string;
  /** client_assertion。不透明な文字列として扱い、検証・分解は行わない。 */
  readonly client_assertion?: string;
  /**
   * DPoP proof JWT（RFC 9449 §4.2）。body には含めず
   * `DPoP: <proof>` ヘッダで送信する。`htu` は `par_endpoint` と一致させること。
   */
  readonly dpop?: DpopProof;
  /**
   * 1 回のユーザー操作に紐づく相関 ID。指定すると `traceparent` /
   * `X-Request-Id` ヘッダで Verifier へ伝播する。続く JAR 取得・`submitPresentation` と
   * **同じ値**を渡すこと。
   */
  readonly correlationContext?: CorrelationContext;
  /** HTTP リクエストに使う `fetch` 実装（テスト注入用）。省略時はグローバル `fetch`。 */
  readonly fetchImpl?: FetchLike;
}

/**
 * OID4VP PAR エンドポイントのレスポンス（RFC 9126 §2.2、OID4VCI の `PARResponse` と同形だが
 * 型は共有しない。理由は `par.ts` 冒頭を参照）。
 *
 * @experimental 公開直後は挙動・シグネチャが変わり得る（v1.0 で `@stable` 昇格予定）。
 */
export interface OID4VPPARResponse {
  /** Verifier が払い出した request_uri（`fetchJAR` / `parsePresentationRequest` に渡す）。 */
  readonly request_uri: string;
  /** request_uri の有効期間（秒）。 */
  readonly expires_in: number;
}

/** `OID4VP_PAR_REQUEST_FAILED`（8031）を組み立てる。`context` には秘密を一切含めない。 */
function parFailed(): VericertsError {
  return new VericertsError(ErrorCodes.OID4VP_PAR_REQUEST_FAILED);
}

/**
 * OID4VP 経路の PAR エンドポイント（Verifier）へ認可パラメータを push し、`request_uri` を
 * 取得する。
 *
 * 手順:
 * 0. 以下はいずれも push 前に `OID4VP_PAR_REQUEST_FAILED`（8031）で拒否する。
 *    - `req.par_endpoint` が HTTPS でない / URL 不正
 *    - `req.state` / `req.code_challenge` / `req.nonce` が空文字・空白のみ
 *    - `req.client_assertion` 指定時に `req.client_assertion_type` が未指定・空文字・空白のみ
 *    - `req.dpop` 指定時にその値が空文字・空白のみ
 * 1. `POST <req.par_endpoint>`（`application/x-www-form-urlencoded`,
 *    body = `response_type=vp_token, client_id, code_challenge, code_challenge_method=S256,
 *    state, nonce, client_assertion + client_assertion_type?`）。`req.dpop` 指定時は body ではなく
 *    `DPoP` ヘッダに載せる。
 * 2. ネットワークエラー / タイムアウト、HTTP 2xx 以外、JSON 不正、`request_uri` / `expires_in`
 *    欠落はすべて `OID4VP_PAR_REQUEST_FAILED`（8031）。
 * 3. `{ request_uri, expires_in }` を返す。
 *
 * @param req push 先エンドポイントと認可パラメータ。
 * @returns `request_uri` と有効期間。
 * @throws `VericertsError`（code `8031`）。
 *
 * @experimental 公開直後は挙動・シグネチャが変わり得る（v1.0 で `@stable` 昇格予定）。
 */
export async function pushAuthorizationRequestForPresentation(
  req: OID4VPPARRequest,
): Promise<OID4VPPARResponse> {
  // 検査後に値が変化しないよう、必須フィールドは一度だけ読む。
  const parEndpoint = req.par_endpoint;
  const state = req.state;
  const codeChallenge = req.code_challenge;
  const nonce = req.nonce;
  if (!isPublicHttpsUrl(parEndpoint)) {
    throw parFailed();
  }
  if (!isNonBlankString(state)) {
    throw parFailed();
  }
  if (!isNonBlankString(codeChallenge)) {
    throw parFailed();
  }
  if (!isNonBlankString(nonce)) {
    throw parFailed();
  }
  // 任意の欄は own 限定で 1 回だけ読む（鎖読みだと未指定の
  // client_assertion / dpop に汚染値が載り、攻撃者の assertion / proof を Verifier へ送出する）。
  const clientAssertion = ownProperty<string>(req, 'client_assertion');
  const clientAssertionType = ownProperty<string>(req, 'client_assertion_type');
  const dpop = ownProperty<string>(req, 'dpop');
  const correlationContext = readCorrelationContext(req);
  const { doFetch, receiver } = resolveInjectedFetch(req);

  // RFC 7521 §4.2: client_assertion_type は client_assertion 使用時に REQUIRED。
  if (clientAssertion !== undefined && !isNonBlankString(clientAssertionType)) {
    throw parFailed();
  }
  // 空の DPoP ヘッダは Verifier 側で形式不正になるだけなので入口で落とす。
  if (dpop !== undefined && !isNonBlankString(dpop)) {
    throw parFailed();
  }

  const params = new URLSearchParams();
  params.set('response_type', RESPONSE_TYPE_VP_TOKEN);
  params.set('client_id', req.client_id);
  params.set('code_challenge', codeChallenge);
  params.set('code_challenge_method', CODE_CHALLENGE_METHOD_S256);
  params.set('state', state);
  params.set('nonce', nonce);
  // client_assertion が無いのに type だけ送っても Verifier 側で解釈できないため対でのみ送る。
  if (clientAssertion !== undefined && clientAssertionType !== undefined) {
    params.set('client_assertion', clientAssertion);
    params.set('client_assertion_type', clientAssertionType);
  }

  const controller = new AbortController();
  // 本文の読み出しまでを 1 つのタイムアウトで覆う（`clearTimeout` は本文読了後）。ヘッダだけ先に
  // 返して本文を引き延ばす AS に無限に待たないため（`internal/http/fetch-json.ts` の不変条件）。
  const timer = setTimeout(() => controller.abort(), PAR_REQUEST_TIMEOUT_MS);
  // 読まずに失敗へ倒す経路でも本文を解放できるよう、`finally` から見える位置で宣言する。
  let response: Response | undefined;
  try {
    try {
      response = await doFetch.call(receiver, parEndpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          Accept: 'application/json',
          // RFC 9449 §5: DPoP proof は body ではなく `DPoP` ヘッダで送る。
          ...(dpop === undefined ? {} : { DPoP: dpop }),
          ...correlationHeaders(correlationContext),
        },
        body: params.toString(),
        // 3xx に追従して client_assertion / DPoP を別ホストへ再送しない。
        redirect: 'manual',
        signal: controller.signal,
      });
    } catch {
      // ネットワークエラー / タイムアウト。詳細は秘密を含み得るため正規化する。
      throw parFailed();
    }

    if (isRedirectedResponse(response)) {
      throw parFailed();
    }

    if (!response.ok) {
      throw parFailed();
    }

    let body: unknown;
    try {
      // 本文も上限（`MAX_DOCUMENT_BYTES` = 1 MiB）の内側で読む。巨大応答でメモリを枯渇させない。
      const text = await readBodyWithinLimit(response);
      if (text === undefined) {
        throw parFailed();
      }
      body = parseJsonWithoutPrototype(text);
    } catch {
      // 本文読み出し中のネットワークエラー / abort / 上限超過 / パース失敗。
      throw parFailed();
    }
    return parseOID4VPPARResponse(body);
  } finally {
    clearTimeout(timer);
    // 本文を読まずに throw した経路が接続を掴んだまま残らないようにする（読了後は no-op）。
    discardBody(response);
  }
}
