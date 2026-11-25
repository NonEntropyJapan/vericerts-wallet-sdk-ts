/**
 * OID4VCI Token Endpoint クライアント（Wallet 側）。
 *
 * Wallet が Token Endpoint に access_token を要求する。送信先 URL とグラント固有の
 * パラメータは呼び出し側から受け取り、Credential Offer の解釈や JWT Proof の生成は別途行う。
 *
 * 対応グラント:
 * - `urn:ietf:params:oauth:grant-type:pre-authorized_code`: pre-authorized_code と
 *   任意の tx_code（PIN）で access_token を取得する。
 *   DPoP proof（RFC 9449）にも対応し、authorization_code 経路と同じく body ではなく
 *   `DPoP` ヘッダで送る（RFC 9449 §5 はグラント種別を問わない）。
 * - `authorization_code`: 認可コードと PKCE `code_verifier` で access_token を取得する。
 *   PKCE（RFC 7636, S256）は このフローで必須で、code_verifier / code_challenge の生成は
 *   `oid4vci-pkce.ts` の `generatePkcePair` が担う。
 *   本経路は Attestation-Based Client Authentication にも対応し、
 *   `client_assertion`（`<WUA>~<WUA-PoP>`）と `client_assertion_type` を対で body に載せる。
 *   判定・送出の不変条件は PAR 経路（`par/par.ts`）と共有する（`oid4vci-client-auth.ts`）。
 *   DPoP proof（RFC 9449）は body ではなく `DPoP` ヘッダで送る。
 *
 * HTTP 送信と応答 JSON の `TokenResponse` 正規化は `oid4vci-token-http.ts` が担い、グラント種別
 * 定数とリクエスト型は `oid4vci-token-types.ts` が担う（`.linterly.yml` 300 行上限）。
 * 本モジュールはグラント固有のパラメータ検査・組み立てに専念する。
 *
 * エラー方針（8010 TOKEN_REQUEST_FAILED）:
 * - 送信前のパラメータ不正（`clientAssertionType` 欠落・非 HTTPS エンドポイント・空の `dpop`）と、
 *   HTTP 非 2xx・通信失敗・レスポンス不正はすべて `TOKEN_REQUEST_FAILED`（8010、再試行不可）
 *   に正規化する（後者の正規化は `oid4vci-token-http.ts`）。いずれも pre-authorized_code /
 *   認可コードの再取得が必要なため再試行で解決しない。
 *
 * セキュリティ上の注意:
 * - 例外メッセージや `context` に pre-authorized_code・tx_code（PIN）・認可コード・
 *   code_verifier・client_assertion・DPoP proof・access_token・c_nonce 等の秘密を一切含めない。
 */

import { ErrorCodes, VericertsError } from '../../../errors.js';
import { readCorrelationContext } from '../../../observability/correlation.js';
import type { Metrics } from '../../../observability/metrics.js';
import { isNonBlankString } from '../../../prototype-safety/non-empty-string.js';
import { ownProperty } from '../../../prototype-safety/own-property.js';
import { readDpopRebuilder } from '../dpop-nonce/index.js';
import { appendClientAssertionParams, assertClientAssertionPair } from '../oid4vci-client-auth.js';
import type { TokenResponse } from './oid4vci-token-http.js';
import { postTokenRequest } from './oid4vci-token-http.js';
import type {
  AuthorizationCodeTokenRequest,
  PreAuthorizedTokenRequest,
} from './oid4vci-token-types.js';
import {
  GRANT_TYPE_AUTHORIZATION_CODE,
  GRANT_TYPE_PRE_AUTHORIZED_CODE,
} from './oid4vci-token-types.js';

export type {
  AuthorizationCodeTokenRequest,
  PreAuthorizedTokenRequest,
} from './oid4vci-token-types.js';
export {
  GRANT_TYPE_AUTHORIZATION_CODE,
  GRANT_TYPE_PRE_AUTHORIZED_CODE,
} from './oid4vci-token-types.js';

/**
 * pre-authorized_code グラントで access_token を取得する。
 *
 * `grant_type=urn:ietf:params:oauth:grant-type:pre-authorized_code` と pre-authorized_code、
 * 任意の tx_code を form-urlencoded で POST する。
 *
 * クライアント認証は authorization_code 経路 / PAR 経路と同一の扱いとする
 * （`oid4vci-client-auth.ts`）。`clientAssertion` を指定しながら `clientAssertionType` が未指定・
 * 空文字・空白のみなら送信前に 8010 で拒否し、`clientAssertionType` だけの指定ではどちらも送らない。
 * Token Endpoint は `clientAssertion` の有無によらず公開ホスト宛の HTTPS に限る（`postTokenRequest` が
 * 送信前に拒否する。`pre-authorized_code` / `tx_code` を平文・内部宛へ送らないため）。
 *
 * `dpop` は body ではなく `DPoP` ヘッダに載せる（RFC 9449 §5 は
 * グラント種別を問わず proof を HTTP ヘッダで送ると定める）。未指定時はヘッダ自体を出さないため
 * `dpop` を渡さない既存の呼び出しの挙動は変わらず、空文字・空白のみは送信前に 8010 で拒否する。
 *
 * @param tokenEndpoint Issuer の Token Endpoint URL（Issuer Metadata の `token_endpoint`）。
 *                      公開ホスト宛の HTTPS 必須。
 * @param request pre-authorized_code と任意の tx_code（PIN）/ client assertion / DPoP proof。
 * @param metrics `vericerts_oid4vci_token_duration_seconds{flow=pre-auth}`
 *                の記録先。未指定なら記録しない。
 * @returns access_token / c_nonce 等を含む `TokenResponse`。
 * @throws Token Request 失敗（code `8010`）。`clientAssertion` に対する `clientAssertionType`
 *         欠落、非 HTTPS / 非公開ホストのエンドポイント、空の `dpop` も同コードで拒否する。
 */
export async function requestTokenPreAuthorized(
  tokenEndpoint: string,
  request: PreAuthorizedTokenRequest,
  metrics?: Metrics,
): Promise<TokenResponse> {
  // **ワイヤに乗る**任意フィールドは例外なく own 限定で 1 回だけ読み、以降はこのローカルだけを使う
  // （authorization_code 経路と同じ方針。同一関数内で読み方が食い違うと監査時に「どれが own 限定か」
  // が読み取れなくなる。`txCode` を鎖読みから揃えたのは）。いずれも純データなので
  // `nonObjectPrototypeProperty` ではなく `ownProperty` を使う（関数値の DI シーム `fetchImpl` は対象外）。
  // 鎖読みだと未指定の正当な呼び出しで攻撃者の assertion / proof / PIN（`tx_code`）が送出される。
  const txCode = ownProperty<string>(request, 'txCode');
  const clientAssertion = ownProperty<string>(request, 'clientAssertion');
  const clientAssertionType = ownProperty<string>(request, 'clientAssertionType');
  const dpop = ownProperty<string>(request, 'dpop');
  const clientAuth = { clientAssertion, clientAssertionType };
  // RFC 7521 §4.2: client_assertion_type は client_assertion 使用時に REQUIRED（PAR と同一判定）。
  assertClientAssertionPair(clientAuth);
  // 空の `DPoP` ヘッダは AS 側で形式不正になるだけなので、入口で落として原因を明確にする
  // （authorization_code 経路と同一判定）。
  if (dpop !== undefined && !isNonBlankString(dpop)) {
    throw new VericertsError(ErrorCodes.TOKEN_REQUEST_FAILED);
  }

  const params = new URLSearchParams();
  params.set('grant_type', GRANT_TYPE_PRE_AUTHORIZED_CODE);
  params.set('pre-authorized_code', request.preAuthorizedCode);
  if (txCode !== undefined) {
    params.set('tx_code', txCode);
  }
  appendClientAssertionParams(params, clientAuth);
  // `request` 自体を DI 元として渡す（PAR 経路が `PARRequest` を渡すのと同じ形）。相関 ID も
  // own 限定で読み、形が壊れていれば未指定として扱う（`readCorrelationContext`）。
  return postTokenRequest(
    tokenEndpoint,
    params,
    dpop,
    request,
    metrics === undefined ? undefined : { metrics, flow: 'pre-auth' },
    readCorrelationContext(request),
    readDpopRebuilder(request),
  );
}

/**
 * authorization_code グラントで access_token を取得する（PKCE 必須）。
 *
 * `grant_type=authorization_code` と認可コード、PKCE `code_verifier`、任意の redirect_uri /
 * client_id / client_assertion（+ client_assertion_type）を form-urlencoded で POST する。
 * code_verifier は Token Request 完了後に呼び出し側で破棄すること。
 *
 * クライアント認証は PAR 経路（`pushAuthorizationRequest`）と同一の
 * 扱いとする（`oid4vci-client-auth.ts`）。`clientAssertion` を指定しながら `clientAssertionType`
 * が未指定・空文字・空白のみなら送信前に 8010 で拒否し、`clientAssertionType` だけの指定では
 * どちらも送らない。
 *
 * `dpop` は body ではなく `DPoP` ヘッダに載せる
 * （RFC 9449 §5）。未指定時はヘッダ自体を出さず、空文字・空白のみは送信前に 8010 で拒否する。
 *
 * @param tokenEndpoint AS の Token Endpoint URL。公開ホスト宛の HTTPS 必須。
 * @param request 認可コード・code_verifier・任意の redirect_uri / client_id / client assertion /
 *                DPoP proof。
 * @param metrics `vericerts_oid4vci_token_duration_seconds{flow=auth-code}`
 *                の記録先。未指定なら記録しない。
 * @returns access_token / c_nonce 等を含む `TokenResponse`。
 * @throws Token Request 失敗（code `8010`）。`clientAssertion` に対する `clientAssertionType`
 *         欠落、非 HTTPS / 非公開ホストのエンドポイント、空の `dpop` も同コードで拒否する。
 */
export async function requestTokenAuthorizationCode(
  tokenEndpoint: string,
  request: AuthorizationCodeTokenRequest,
  metrics?: Metrics,
): Promise<TokenResponse> {
  // 任意フィールドはいずれも純データのワイヤパラメータであり、プロトタイプメソッドで提供される
  // 正当な形は存在しない。鎖読みだと未指定の `clientAssertion` 等に `Object.prototype` の汚染値が
  // 載り、攻撃者の assertion を AS へ送出しうる。同一関数内で読み方が食い違うと
  // 監査時に「どれが own 限定か」が読み取れなくなるため、`redirectUri` / `clientId` / `dpop` も
  // 含めて own 限定で 1 回だけ読み、以降はこのローカルだけを使う（PAR 経路と同じ方針）。
  // `dpop` を鎖読みすると、指定していない正当な呼び出しで攻撃者の proof が `DPoP` ヘッダに載る。
  const redirectUri = ownProperty<string>(request, 'redirectUri');
  const clientId = ownProperty<string>(request, 'clientId');
  const clientAssertion = ownProperty<string>(request, 'clientAssertion');
  const clientAssertionType = ownProperty<string>(request, 'clientAssertionType');
  const dpop = ownProperty<string>(request, 'dpop');
  const clientAuth = { clientAssertion, clientAssertionType };
  // RFC 7521 §4.2: client_assertion_type は client_assertion 使用時に REQUIRED（PAR と同一判定）。
  assertClientAssertionPair(clientAuth);
  // 空の `DPoP` ヘッダは AS 側で形式不正になるだけなので、入口で落として原因を明確にする。
  if (dpop !== undefined && !isNonBlankString(dpop)) {
    throw new VericertsError(ErrorCodes.TOKEN_REQUEST_FAILED);
  }

  const params = new URLSearchParams();
  params.set('grant_type', GRANT_TYPE_AUTHORIZATION_CODE);
  params.set('code', request.code);
  params.set('code_verifier', request.codeVerifier);
  if (redirectUri !== undefined) {
    params.set('redirect_uri', redirectUri);
  }
  if (clientId !== undefined) {
    params.set('client_id', clientId);
  }
  appendClientAssertionParams(params, clientAuth);
  return postTokenRequest(
    tokenEndpoint,
    params,
    dpop,
    request,
    metrics === undefined ? undefined : { metrics, flow: 'auth-code' },
    readCorrelationContext(request),
    readDpopRebuilder(request),
  );
}
