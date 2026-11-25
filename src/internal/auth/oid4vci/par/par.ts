/**
 * OID4VCI Authorization Code Flow の Pushed Authorization Request（PAR, RFC 9126）クライアント。
 *
 * 本モジュールは Wallet（Holder）が Authorization Server（AS）の PAR エンドポイントへ
 * 認可パラメータを push し、`request_uri` を取得するクライアント側処理のみを担う。
 * 続く認可 URL の組み立ては `oid4vci-authz-url.ts` の `buildAuthorizationUrl`。
 *
 * PAR は「フロントチャネルに認可パラメータを載せない」ための仕組みで、認可コード傍受やパラメータ改ざんを
 * 無効化する。本 SDK では PAR を必須とし、PKCE
 * （`oid4vci-pkce.ts` の `generatePkcePair`）と Wallet Attestation（`client_assertion` = `<WUA>~<WUA-PoP>`）を
 * 併用する。WUA-PoP / DPoP JWT の生成・Token Request・Credential Request は本モジュールの責務外で、
 * 本モジュールは push 済みパラメータを `PARRequest` 1 引数で受け取る。
 *
 * スコープ外（別フェーズ／別モジュールの責務）:
 * - Issuer / AS Metadata 取得、WUA-PoP / DPoP proof / PKCE 値の生成（呼び出し側が生成して `req` に詰める）。
 * - ブラウザ / Custom Tab の起動、Deep Link コールバック受領（プラットフォーム層の責務）。
 *
 * エラー方針:
 * - HTTP 非 2xx（OAuth エラー JSON `{ error, error_description }` を含む）、レスポンス JSON 不正・
 *   `request_uri` / `expires_in` 欠落はすべて `TOKEN_REQUEST_FAILED`（8010, 再試行不可）に正規化する。
 *   PAR は access_token 取得フローの起点であり、失敗時は code_challenge / client_assertion の
 *   再生成からやり直す必要があるため Token Request と同じ扱いとする。
 * - ネットワーク失敗・タイムアウトは `ISSUER_COMMUNICATION_FAILED`（3004, 再試行可）に正規化する。
 *
 * セキュリティ上の注意:
 * - 例外メッセージや `context` に client_assertion（`<WUA>~<WUA-PoP>`）・code_challenge・request_uri・
 *   authorization_details 等を含めない。
 * - PAR は client_assertion（`<WUA>~<WUA-PoP>`）を平文 body で送るため、HTTPS 以外のエンドポイントは拒否する。
 * - レスポンス本文に request_uri 等が含まれるため、JSON parse 失敗時に `cause` を渡さず正規化する。
 */

import { ErrorCodes, VericertsError } from '../../../errors.js';
import type { FetchLike } from '../../../fetch-di.js';
import { resolveInjectedFetch } from '../../../fetch-di.js';
import { discardBody, readBodyWithinLimit } from '../../../http/body-limit.js';
import { isPublicHttpsUrl, isRedirectedResponse } from '../../../http/public-https-url.js';
import type { CorrelationContext } from '../../../observability/correlation.js';
import { correlationHeaders, readCorrelationContext } from '../../../observability/correlation.js';
import { isNonBlankString } from '../../../prototype-safety/non-empty-string.js';
import { ownProperty } from '../../../prototype-safety/own-property.js';
import { parseJsonWithoutPrototype } from '../../../prototype-safety/parse-json.js';
import type { DpopProof } from '../../dpop/dpop-common.js';
import type { DpopProofRebuilder } from '../dpop-nonce/index.js';
import { readDpopRebuilder, sendWithDpopNonceRetry } from '../dpop-nonce/index.js';
import { appendClientAssertionParams, assertClientAssertionPair } from '../oid4vci-client-auth.js';
import { CODE_CHALLENGE_METHOD_S256, RESPONSE_TYPE_CODE } from './params.js';
import { parsePARResponse } from './response.js';

/** PAR Request のタイムアウト（ミリ秒）。Token Request と揃えて 30 秒。 */
const PAR_REQUEST_TIMEOUT_MS = 30_000;

/**
 * RFC 9396 Rich Authorization Requests の authorization details オブジェクト。
 *
 * `type` のみ必須で、他のメンバは認可タイプごとに定義される（OID4VCI では
 * `credential_configuration_id` / `credential_identifiers` / `format` 等）。本 SDK は
 * `type` 以外を検証・正規化せずそのまま JSON 文字列化して送る不透明パススルーとして扱う。
 * RFC 9396 上メンバの妥当性は認可タイプと AS の定義に依存するため、SDK 側で individual member を
 * 検証すると AS が受理する正当な認可詳細を Wallet 側で先に落としうる。
 *
 * @experimental 挙動・シグネチャが変わることがある（v1.0 で `@stable` 昇格予定）。
 */
export interface OAuth2AuthzDetails {
  /** 認可詳細の種別。OID4VCI では `"openid_credential"`。 */
  readonly type: string;
  /** 認可タイプ固有のメンバ（検証せずそのまま送信する）。 */
  readonly [key: string]: unknown;
}

/**
 * PAR エンドポイントへ push する認可パラメータ。
 *
 * `client_assertion`（`<WUA>~<WUA-PoP>`）・`code_challenge`（PKCE）は呼び出し側が生成して詰める。
 * `authorization_details` は OID4VCI の `authorization_details`（`[{ type: "openid_credential", ... }]`）で、
 * object 配列を JSON 文字列化して送信する。
 *
 * 命名規約（snake_case と camelCase の混在は意図的）:
 * - `par_endpoint` は送信先 URL で、body に含めない。`client_id` などの認可パラメータは
 *   RFC 9126 のリクエストで送る名前をそのまま使う。
 * - `fetchImpl`（DI seam）と `correlationContext`（相関 ID。ヘッダに載る）はワイヤの body に
 *   乗る送信パラメータではない。SDK 内の他のオプション型（`oid4vci.ts` の
 *   `RequestCredentialOptions`）に揃えて camelCase とする。
 *
 * @experimental 挙動・シグネチャが変わることがある（v1.0 で `@stable` 昇格予定）。
 */
export interface PARRequest {
  /** AS の `pushed_authorization_request_endpoint`（HTTPS 必須）。 */
  readonly par_endpoint: string;
  /** Wallet の client_id（AS 登録済み）。 */
  readonly client_id: string;
  /** PKCE code_challenge（`BASE64URL(SHA256(code_verifier))`, `generatePkcePair` の戻り）。 */
  readonly code_challenge: string;
  /** 認可後のコールバック先（カスタムスキーム等）。AS 登録済み URI と一致させる。 */
  readonly redirect_uri: string;
  /** 要求する credential_configuration_id（OAuth scope）。 */
  readonly scope?: string;
  /** OID4VCI authorization_details（`[{ type: "openid_credential", ... }]`）。 */
  readonly authorization_details?: readonly OAuth2AuthzDetails[];
  /**
   * CSRF 防止 state（`crypto.getRandomValues` 由来 128-bit 以上）。
   *
   * リダイレクト受領時に完全一致を確かめるため、PAR の前に必ず生成する。
   * 空文字・空白のみは送信前に 8010 で拒否する。
   */
  readonly state: string;
  /**
   * client_assertion_type（RFC 7521 §4.2 が `client_assertion` 使用時に REQUIRED と定める）。
   *
   * SDK は既定値を持たない。`client_assertion` を指定する場合は本フィールドも必ず指定すること
   * （未指定・空文字・空白のみは push 前に 8010 で拒否する）。Wallet Attestation を
   * 使う場合は公開定数 `WUA_CLIENT_ASSERTION_TYPE` を指定する。
   * それでも既定値を補完しないのは、`client_assertion` が Wallet Attestation なのか RFC 7523 の
   * `jwt-bearer` assertion なのかを SDK からは判別できず、既定値を補うと別形式の assertion を
   * 誤ってラベル付けして送信しうるため。`client_assertion` が指定されている場合にのみ送信する。
   */
  readonly client_assertion_type?: string;
  /**
   * client_assertion。AS が Attestation-Based Client Auth を要求する場合に指定。
   *
   * Wallet Attestation を使う場合の値は WUA JWT と WUA-PoP JWT を `~` で連結した
   * `<WUA>~<WUA-PoP>` で、
   * `buildClientAttestation`（`internal/eudi/wua/proof.ts`）の `clientAssertion` がこの形を返す。
   * PAR 経路と Token Request 経路で形式の使い分けはしない。
   * SDK にとっては不透明な文字列であり、内容の検証・組み立て・分解は行わずそのまま送信する。
   */
  readonly client_assertion?: string;
  /**
   * DPoP proof JWT（RFC 9449 §4.2）。
   *
   * 他の snake_case フィールドと異なり body には載らず `DPoP: <proof>` ヘッダとして送信される
   * （RFC 9126 §2 が PAR を Token Endpoint と同じバックチャネル要求と定め、RFC 9449 §5 が proof を
   * HTTP ヘッダで送ると定めるため）。呼び出し側が
   * `createDpopProof({ htm: 'POST', htu: <par_endpoint> }, signer)` で生成し、`htu` を
   * `par_endpoint` と一致させること（不一致だと AS が束縛検証で拒否する）。空文字・空白のみは
   * push 前に 8010 で拒否する。
   */
  readonly dpop?: DpopProof;
  /** `use_dpop_nonce`（RFC 9449 §8）を受けたときの nonce 付き proof 再生成関数。1 回だけ再送する。 */
  readonly rebuildDpop?: DpopProofRebuilder;
  /**
   * 1 回のユーザー操作に紐づく相関 ID。指定すると `traceparent` /
   * `X-Request-Id` ヘッダで AS へ伝播する。`dpop` と同じく body には載らない。続く Token /
   * Credential Request と**同じ値**を渡すこと（1 回の受領フローを 1 本のトレースにするため）。
   * 未指定ならヘッダ自体を出さない。ワイヤパラメータではないため camelCase とする。
   */
  readonly correlationContext?: CorrelationContext;
  /**
   * HTTP リクエストに使う `fetch` 実装（テスト注入用）。省略時はグローバル `fetch`。ワイヤに
   * 乗らない DI seam のため camelCase とする。prototype メソッドでの実装も受け付けるが、
   * `Object.prototype` 由来の値は採用しない（`internal/fetch-di.ts`）。
   */
  readonly fetchImpl?: FetchLike;
}

/**
 * PAR エンドポイントの応答（`201 { request_uri, expires_in }`）。フィールド名は AS の応答 JSON と同じ。
 *
 * @experimental 挙動・シグネチャが変わることがある（v1.0 で `@stable` 昇格予定）。
 */
export interface PARResponse {
  /** AS が払い出した request_uri（認可 URL に載せる, RFC 9126）。 */
  readonly request_uri: string;
  /** request_uri の有効期間（秒）。期限内に認可 URL を開く必要がある。 */
  readonly expires_in: number;
}

/**
 * PAR エンドポイントへ認可パラメータを push し、`request_uri` を取得する。
 *
 * 手順:
 * 0. 以下はいずれも push 前に `TOKEN_REQUEST_FAILED`（8010）で拒否する。
 *    - `req.par_endpoint` が HTTPS でない / URL 不正（client_assertion の平文漏えい防止）
 *    - `req.state` が空文字・空白のみ（CSRF 防止照合が無意味になる）
 *    - `req.code_challenge` が空文字・空白のみ（PKCE を必須とし、空値では結び付かない）
 *    - `req.client_assertion` 指定時に `req.client_assertion_type` が未指定・空文字・空白のみ
 *      （RFC 7521 §4.2 が REQUIRED。SDK が決め打つと意図しない認証方式で送信されうる）
 *    - `req.dpop` 指定時にその値が空文字・空白のみ（`req.dpop` は own 限定で読む）
 *    任意フィールドはいずれも own 限定で 1 回だけ読み、ガードと送出で同じ値を使う。ガードと
 *    送出の両方で使う必須フィールド（`par_endpoint` / `state` / `code_challenge`）も冒頭で
 *    1 回だけ読む（必須なので own 限定にはせず素の 1 回読み）。DI seam の `req.fetchImpl` だけは
 *    `Object.prototype` 由来のみを除いて読む（`internal/fetch-di.ts`）。
 * 1. `POST <req.par_endpoint>`（`application/x-www-form-urlencoded`,
 *    body = `response_type=code, client_id, code_challenge, code_challenge_method=S256,
 *    redirect_uri, state, scope?, authorization_details?, client_assertion + client_assertion_type?`）。
 *    `client_assertion` と `client_assertion_type` は対で送る（片方だけの送信はしない）。
 *    `req.dpop` 指定時は body ではなく `DPoP` ヘッダに載せる（RFC 9449 §5）。
 * 2. ネットワークエラー / タイムアウトは `ISSUER_COMMUNICATION_FAILED`（3004, 再試行可）。
 * 3. HTTP 2xx 以外 / JSON 不正 / `request_uri`・`expires_in` 欠落は `TOKEN_REQUEST_FAILED`（8010）。
 * 4. `{ request_uri, expires_in }` を返す（認可 URL 構築は `buildAuthorizationUrl`）。
 *
 * @param req push 先エンドポイントと認可パラメータ
 *            （par_endpoint / client_id / code_challenge / redirect_uri / state 等）。
 * @returns `request_uri` と有効期間。
 * @throws `VericertsError`。通信失敗は code `3004`、応答不正 / push 失敗 / 非 HTTPS エンドポイント /
 *         空の `state` / 空の `code_challenge` / `client_assertion` に対する
 *         `client_assertion_type` 欠落 / 空の `dpop` は code `8010`。
 *
 * @experimental 挙動・シグネチャが変わることがある（v1.0 で `@stable` 昇格予定）。
 */
export async function pushAuthorizationRequest(req: PARRequest): Promise<PARResponse> {
  // ガードと送出の両方で使う必須フィールドは、ここで 1 回だけ読んで以降はこのローカルだけを使う。
  // `PARRequest` はアクセサや prototype メソッドでメンバを公開するクラスインスタンスでもよいため、
  // 読み直すと 1 回目と 2 回目で別の値が返り得る（TOCTOU）。とくに `par_endpoint` を読み直すと、
  // HTTPS ガードを通した URL とは別の `http://` 送信先へ client_assertion（`<WUA>~<WUA-PoP>`）を平文送信
  // しうる。必須フィールドなので own 限定にはしない（own 限定にすると上記のクラス実装が壊れる）。
  const parEndpoint = req.par_endpoint;
  const state = req.state;
  const codeChallenge = req.code_challenge;
  // client_assertion（`<WUA>~<WUA-PoP>`）を平文 body で送るため、HTTPS 以外のエンドポイントは拒否する。
  if (!isPublicHttpsUrl(parEndpoint)) {
    throw new VericertsError(ErrorCodes.TOKEN_REQUEST_FAILED);
  }
  // state は CSRF 防止の要。空文字・空白のみは照合が無意味になるため push 前に拒否する。
  if (!isNonBlankString(state)) {
    throw new VericertsError(ErrorCodes.TOKEN_REQUEST_FAILED);
  }
  // code_challenge は PKCE の要（PKCE に必要）。空値のまま push すると PKCE の
  // 結び付きが無い認可要求が成立しうるため、state と同じく入口で拒否する。
  if (!isNonBlankString(codeChallenge)) {
    throw new VericertsError(ErrorCodes.TOKEN_REQUEST_FAILED);
  }
  // 純データの任意欄は own 限定で 1 回だけ読み、以降のガードと送出で同じ値を使う（読み直すと
  // 検査した範囲と送る範囲がずれる）。鎖読みだと未指定の `scope` / `authorization_details` /
  // `client_assertion` / `dpop` に汚染値が載り、攻撃者の assertion や proof を AS へ送出する。
  const scope = ownProperty<string>(req, 'scope');
  const authzDetails = ownProperty<readonly OAuth2AuthzDetails[]>(req, 'authorization_details');
  const clientAssertion = ownProperty<string>(req, 'client_assertion');
  const clientAssertionType = ownProperty<string>(req, 'client_assertion_type');
  const dpop = ownProperty<string>(req, 'dpop');
  // 相関 ID も純データなので own 限定で読む。形が壊れていれば未指定として扱う。
  const correlationContext = readCorrelationContext(req);
  // `fetchImpl` は prototype メソッドでの DI が正当なため own 限定にできない（ほかの取得経路と
  // レシーバの束ね直しは `internal/fetch-di.ts` を参照）。
  const { doFetch, receiver } = resolveInjectedFetch(req);
  // RFC 7521 §4.2: client_assertion_type は client_assertion 使用時に REQUIRED。SDK が既定値を
  // 決め打ちすると呼び出し側が意図しないクライアント認証方式で送信されうるため、明示を要求する。
  // 判定は Token Request 経路（`oid4vci-token.ts`）と共有する（RFC 9126 §2 が PAR のクライアント
  // 認証を Token Endpoint と同一に扱うため、経路ごとに判定がずれてはならない）。
  const clientAuth = { clientAssertion, clientAssertionType };
  assertClientAssertionPair(clientAuth);
  // 空の `DPoP` ヘッダは AS 側で形式不正になるだけなので、入口で落として原因を明確にする。
  if (dpop !== undefined && !isNonBlankString(dpop)) {
    throw new VericertsError(ErrorCodes.TOKEN_REQUEST_FAILED);
  }

  const params = new URLSearchParams();
  params.set('response_type', RESPONSE_TYPE_CODE);
  params.set('client_id', req.client_id);
  params.set('code_challenge', codeChallenge);
  params.set('code_challenge_method', CODE_CHALLENGE_METHOD_S256);
  params.set('redirect_uri', req.redirect_uri);
  if (scope !== undefined) {
    params.set('scope', scope);
  }
  if (authzDetails !== undefined) {
    params.set('authorization_details', JSON.stringify(authzDetails));
  }
  params.set('state', state);
  // client_assertion が無いのに type だけ送っても AS 側で解釈できないため、対でのみ送る
  // （type だけの指定は上のガードを通り抜けるが、ここでどちらも送らない）。
  appendClientAssertionParams(params, clientAuth);

  const controller = new AbortController();
  // 本文の読み出しまでを 1 つのタイムアウトで覆う。ヘッダだけ先に返して本文を引き延ばす AS に無限に待たない（`fetch-json.ts`）。
  const timer = setTimeout(() => controller.abort(), PAR_REQUEST_TIMEOUT_MS);
  // 読まずに失敗へ倒す経路でも本文を解放できるよう、`finally` から見える位置で宣言する。
  let response: Response | undefined;
  try {
    try {
      // `use_dpop_nonce`（RFC 9449 §8）なら nonce 付き proof で 1 回だけ再送。fetch は取り出し元をレシーバに束ねて呼ぶ。
      response = await sendWithDpopNonceRetry(
        (proof) =>
          doFetch.call(receiver, parEndpoint, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/x-www-form-urlencoded',
              Accept: 'application/json',
              // RFC 9449 §5: proof は `DPoP` ヘッダで送る。未指定時はヘッダ自体を出さない（空ヘッダは形式不正になりうる）。
              ...(proof === undefined ? {} : { DPoP: proof }),
              // 相関 ID を指定したときだけヘッダを送る。
              ...correlationHeaders(correlationContext),
            },
            body: params.toString(),
            redirect: 'manual', // 3xx に追従して client_assertion / DPoP を別ホストへ再送しない
            signal: controller.signal,
          }),
        dpop,
        readDpopRebuilder(req),
      );
    } catch {
      // ネットワークエラー / タイムアウト（abort）。詳細は秘密を含み得るため正規化する。
      throw new VericertsError(ErrorCodes.ISSUER_COMMUNICATION_FAILED);
    }

    // 非 2xx（invalid_request / invalid_client / OAuth エラー JSON 等）・リダイレクトはすべて失敗扱い。
    // 本文は読み取らず正規化する（本文に request_uri / エラー詳細が含まれ得る）。
    if (!response.ok || isRedirectedResponse(response)) {
      throw new VericertsError(ErrorCodes.TOKEN_REQUEST_FAILED);
    }

    let body: unknown;
    try {
      // 本文も上限（`MAX_DOCUMENT_BYTES` = 1 MiB）の内側で読む。巨大応答でメモリを枯渇させない。
      const text = await readBodyWithinLimit(response);
      if (text === undefined) {
        throw new VericertsError(ErrorCodes.TOKEN_REQUEST_FAILED);
      }
      // null プロトタイプで応答を読み、parsePARResponse でも自身のプロパティに限定する。
      body = parseJsonWithoutPrototype(text);
    } catch {
      // 本文読み出し中のネットワークエラー / abort / 上限超過 / パース失敗。
      throw new VericertsError(ErrorCodes.TOKEN_REQUEST_FAILED);
    }
    return parsePARResponse(body);
  } finally {
    clearTimeout(timer);
    // 本文を読まずに throw した経路が接続を掴んだまま残らないようにする（読了後は no-op）。
    discardBody(response);
  }
}
