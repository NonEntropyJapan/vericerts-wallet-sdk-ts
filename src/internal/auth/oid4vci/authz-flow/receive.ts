/**
 * OID4VCI Authorization Code Flow（PAR + PKCE）のオーケストレーション。
 *
 * HAIP の Authorization Code Flow で使う PAR（RFC 9126）、ブラウザでの認可、
 * Token Request、JWT Proof の生成、Credential Request を順に実行する。
 * 呼び出し側が渡す4つのエンドポイントはフローの入口で HTTPS であることを検査する。
 * 署名には呼び出し側の署名器を使い、通信のタイムアウトは各リクエスト処理が扱う。
 * Offer URI から Issuer / AS Metadata とエンドポイントを解決する場合は `receiveCredential` を使う。
 *
 * 処理の順序:
 *
 * 1. PKCE ペア生成（`generatePkcePair`、S256 固定）
 * 2. CSRF 防止 `state` 生成（`generateNonce` の 128-bit）
 * 3. PAR push → `request_uri` 取得（`pushAuthorizationRequest`）
 * 4. 認可 URL 組み立て（`buildAuthorizationUrl`。載るのは `client_id` と `request_uri` のみ）
 * 5. ブラウザ / Custom Tab で認可（`deps.authorize` で DI。プラットフォーム層の責務）
 * 6. `state` 完全一致の照合（不一致は fail-closed）
 *    加えて認可応答の `iss`（RFC 9207）を AS Metadata の `issuer` と完全一致で照合する
 *    （AS mix-up 対策。欠落・不一致は Token Request の前に fail-closed）
 * 7. 認可コード + `code_verifier` で access_token / c_nonce 取得（`requestTokenAuthorizationCode`）
 * 8. JWT Proof 生成（`generateProofJWT`。`nonce` は Token Response の `c_nonce` → Nonce Endpoint →
 *    省略の順で解決し（`resolveProofNonce`）、`aud` は Credential Issuer Identifier）
 * 9. Credential Endpoint から VC 受領（`requestCredential`。`token_type: "DPoP"` かつ
 *    `deps.createDpopProof` 指定時のみ、`credentialEndpoint` を `htu`、access_token を `ath` の
 *    元とする DPoP proof を載せる）
 *
 * スコープ外（別モジュール／別フェーズの責務）:
 * - Issuer Metadata / AS Metadata 取得によるエンドポイント解決（呼び出し側が `endpoints` で渡す。
 *   OID4VCI の well-known 取得は `eudi/issuance/metadata.ts`）。
 * - 遅延発行（Deferred Endpoint ポーリング、未対応）。`requestCredential` の
 *   `{ status: 'deferred', transactionId }` を**そのまま返す**（拒否しない。判断は呼び出し側）。
 * - WUA-PoP の `nonce` に AS の `c_nonce` を載せる運用。`clientAssertion` は不透明な
 *   文字列として受け取り、そのまま PAR と Token Request の両方へ載せる（`types.ts` に理由）。
 * - 受領した VC の署名検証・永続化（呼び出し側の責務。`requestCredential` と同じ契約）。
 *
 * 読み取りの責務分割: 呼び出し側入力の own 限定読みと検証は `deps.ts`（依存）と `options.ts`
 * （要求内容・4 エンドポイント）が持ち、本モジュールは「AS / Issuer と何を順に話すか」だけを持つ。
 *
 * セキュリティ上の注意:
 * - `options` / リダイレクト値は分割代入せず own 限定で 1 回だけ読む（`options.ts`）。とくに
 *   `redirectUri` / `clientId` を鎖読みすると、指定していない正当な呼び出しで `Object.prototype`
 *   の汚染値が「AS 登録済みのコールバック先」として PAR に push され、認可コードが攻撃者へ返る。
 * - 下流へ渡すオプションには `fetchImpl` を**常に own プロパティとして**載せる（値が `undefined`
 *   でも載せる）。載せずに省略すると、下流の `resolveInjectedFetch` がそのリテラルのプロトタイプ鎖を
 *   辿って `Object.prototype.fetchImpl` を掴み、client_assertion・access_token・受領 VC ごと
 *   攻撃者の実装へ渡る。
 * - 4 つのエンドポイントは**本フローの入口で 4 つとも HTTPS を要求する**（`options.ts` の `resolveEndpoints`）。
 *   下流の `requestTokenAuthorizationCode` の HTTPS 検査は `clientAssertion` 指定時のみの
 *   条件付きで、後方互換のため無条件化できない。委譲だけにすると `clientAssertion` 未指定の
 *   呼び出しで `http://` の Token Endpoint が素通りし、認可コード・`code_verifier`・
 *   `access_token` が平文で流れる。
 * - **DPoP proof は送信先ごとに生成する**（RFC 9449 §4.3 の `htu` 束縛）。PAR / Token / Credential の
 *   3 経路で 1 つの proof を共用すると AS / Issuer が束縛検証で拒否する。Credential Endpoint 用の proof は
 *   `credentialEndpoint` を `htu` として生成する。
 * - `createDpopProof` を渡していないのに AS が **DPoP 束縛の access_token**（`token_type: "DPoP"`）を
 *   返した場合は、`requestCredential` が Credential Request を送らず `8020`
 *   （`reason: "dpop_proof_required"`）で落とす（fail-closed）。Bearer で送っても RFC 9449 §7.1
 *   準拠の Issuer が拒否するだけであり、access_token を平文で 1 度も送らない方が露出面が小さい。
 * - `state` の照合は `timingSafeEqualString` で行う（`===` は先頭一致長で早期に返るため、
 *   リダイレクトを何度も投げられる攻撃者に 1 バイトずつ探索させる余地を与える）。
 * - **`iss` の照合は必須で、欠落も拒否する**（RFC 9700 §4.4）。Offer の `credential_issuer` は攻撃者が
 *   選べるため、攻撃者の AS Metadata が正規 AS の `authorization_endpoint` を告知すると、正規 AS が
 *   発行した認可コードと `code_verifier` が攻撃者の Token Endpoint へ送られる。`state` は攻撃者が
 *   知っているので防げない。`redirect_uri` / `client_id` は AS 共通の 1 組なので AS ごとの分離でも
 *   防げない。そのため `iss` を返さない AS は本フローでは利用できない。
 * - 例外の `context` は固定識別子のみ。認可コード・`code_verifier`・`state`・client_assertion・
 *   access_token・c_nonce・URL・`cause` を一切載せない。
 */

import { ownProperty } from '../../../prototype-safety/own-property.js';
import { timingSafeEqualString } from '../../../timing-safe.js';
import { generateNonce } from '../../nonce/generate.js';
import { dpopProofRebuilder } from '../dpop-nonce/index.js';
import type { RequestCredentialResult } from '../oid4vci.js';
import { generateProofJWT, requestCredential } from '../oid4vci.js';
import { buildAuthorizationUrl } from '../oid4vci-authz-url.js';
import { credentialRequestDpop } from '../oid4vci-credential-dpop.js';
import { generatePkcePair } from '../oid4vci-pkce.js';
import { resolveProofNonce } from '../oid4vci-proof-nonce.js';
import { pushAuthorizationRequest } from '../par/index.js';
import { requestTokenAuthorizationCode } from '../token/oid4vci-token.js';
import type { ResolvedFlowDeps } from './deps.js';
import { resolveFlowDeps } from './deps.js';
import { flowFailure, resolveOptions } from './options.js';
import type { AuthorizationCodeFlowDeps, AuthorizationCodeFlowOptions } from './types.js';

/**
 * 認可 URL を開き、返った `code` を `state` 照合のうえ取り出す。
 *
 * `authorize` は呼び出し側の実装であり、`JSON.parse` を通らないオブジェクトを返す。したがって
 * `code` / `state` は own 限定で読む。鎖読みだと、`code` を持たない戻り値が
 * `Object.prototype.code` の汚染値を拾い、攻撃者の認可コードで Token Request が成立する。
 *
 * `state` は PAR で push した値と**完全一致**しなければならない（CSRF 防止）。一致しない
 * リダイレクトは別セッション由来か注入であり、認可コードを使わずに落とす。
 *
 * `iss`（RFC 9207）は AS Metadata の `issuer` と**完全一致**（単純な文字列比較。同 §2.4）しなければ
 * ならず、欠落も拒否する（AS mix-up 対策。RFC 9700 §4.4）。認可コードは本関数が `iss` を確認した
 * 後にしか呼び出し側へ戻らない = Token Request が飛ぶのはその後だけである。
 */
async function authorizeAndVerify(
  authorizationUrl: string,
  expectedState: string,
  expectedIssuer: string,
  deps: ResolvedFlowDeps,
): Promise<string> {
  let redirect: unknown;
  try {
    redirect = await deps.authorize(authorizationUrl);
  } catch {
    // ユーザー拒否・タイムアウト・Deep Link 受領失敗。URL や例外詳細は載せない。
    throw flowFailure('authorization_failed');
  }
  if (typeof redirect !== 'object' || redirect === null) {
    throw flowFailure('invalid_authorization_redirect');
  }
  const code = ownProperty<unknown>(redirect, 'code');
  const state = ownProperty<unknown>(redirect, 'state');
  if (typeof code !== 'string' || code.length === 0 || typeof state !== 'string') {
    throw flowFailure('invalid_authorization_redirect');
  }
  // 早期 return する `===` は先頭一致長を漏らす（リダイレクトを繰り返し投げる攻撃者に
  // 1 バイトずつ `state` を探索させうる）。
  if (!timingSafeEqualString(state, expectedState)) {
    throw flowFailure('state_mismatch');
  }
  const iss = ownProperty<unknown>(redirect, 'iss');
  if (iss === undefined) {
    throw flowFailure('iss_missing');
  }
  if (typeof iss !== 'string' || iss !== expectedIssuer) {
    throw flowFailure('iss_mismatch');
  }
  return code;
}

/**
 * OID4VCI Authorization Code Flow（PAR + PKCE）で VC を受領する。
 *
 * 手順は本ファイル冒頭の 1〜9 のとおり。`state` と PKCE `code_verifier` はフロー内で生成して
 * フロー内で使い切る（呼び出し側に保持させると、照合を省いた実装や `code_verifier` を
 * ログへ出す実装が生まれる）。
 *
 * @param options エンドポイント・client_id・redirect_uri・要求フォーマット / definition・
 *                scope / authorization_details・client assertion。
 * @param deps 署名鍵・Holder DID / kid・認可 UI 起動関数・HTTP シーム・DPoP proof 生成関数。
 * @returns 即時受信 VC（`{ status: 'issued', credential, cNonce }`）または遅延発行の取引 ID
 *          （`{ status: 'deferred', transactionId, cNonce }`）。署名検証・永続化は呼び出し側の責務。
 * @throws `VericertsError`。依存 / オプション不正・非 HTTPS エンドポイント・PAR push 失敗・
 *         認可失敗・`state` 不一致・Token Request 失敗は code `8010`、通信失敗は `3004`、
 *         Credential Request 失敗は `8020`。
 *
 * @experimental 挙動・シグネチャが変わることがある（v1.0 で `@stable` 昇格予定）。
 */
export async function receiveCredentialViaAuthorizationCode(
  options: AuthorizationCodeFlowOptions,
  deps: AuthorizationCodeFlowDeps,
): Promise<RequestCredentialResult> {
  const resolved = resolveFlowDeps(deps);
  const opts = resolveOptions(options);
  const endpoints = opts.endpoints;

  // 1〜2. PKCE（S256 必須）と CSRF 防止 state（128-bit）。どちらもフロー内で生成し使い切る。
  const pkce = generatePkcePair();
  const state = generateNonce();

  // 3. PAR push。DPoP proof は送信先ごとに `htu` が違うため個別に生成する。
  const parDpop = resolved.createDpopProof?.(endpoints.parEndpoint);
  const pushed = await pushAuthorizationRequest({
    par_endpoint: endpoints.parEndpoint,
    client_id: opts.clientId,
    code_challenge: pkce.codeChallenge,
    redirect_uri: opts.redirectUri,
    state,
    scope: opts.scope,
    authorization_details: opts.authorizationDetails,
    client_assertion: opts.clientAssertion,
    client_assertion_type: opts.clientAssertionType,
    dpop: parDpop,
    // `use_dpop_nonce`（RFC 9449 §8）を受けたら nonce 付き proof で 1 回だけ再送する。
    rebuildDpop: dpopProofRebuilder(resolved.createDpopProof, endpoints.parEndpoint),
    // 相関 ID は PAR / Token / Credential で同一の値を載せる（1 回の受領操作 = 1 トレース）。
    correlationContext: resolved.correlationContext,
    // 値が undefined でも own プロパティとして載せ、下流の DI 解決が汚染値を掴まないようにする。
    fetchImpl: resolved.fetchImpl,
  });

  // 4〜6. 認可 URL を開き、`state` 完全一致を確認して認可コードを取り出す。
  const authorizationUrl = buildAuthorizationUrl(
    endpoints.authorizationEndpoint,
    opts.clientId,
    pushed.request_uri,
  );
  const code = await authorizeAndVerify(
    authorizationUrl,
    state,
    opts.authorizationServerIssuer,
    resolved,
  );

  // 7. access_token / c_nonce 取得。`redirect_uri` は PAR で push した値と同一を送る
  //    （RFC 6749 §4.1.3。AS 側の一致検査を通すため）。
  const tokenDpop = resolved.createDpopProof?.(endpoints.tokenEndpoint);
  const token = await requestTokenAuthorizationCode(endpoints.tokenEndpoint, {
    code,
    codeVerifier: pkce.codeVerifier,
    redirectUri: opts.redirectUri,
    clientId: opts.clientId,
    clientAssertion: opts.clientAssertion,
    clientAssertionType: opts.clientAssertionType,
    dpop: tokenDpop,
    rebuildDpop: dpopProofRebuilder(resolved.createDpopProof, endpoints.tokenEndpoint),
    correlationContext: resolved.correlationContext,
    fetchImpl: resolved.fetchImpl,
  });

  // 8. JWT Proof。`nonce` は Token Response の `c_nonce`（旧 Draft）→ Nonce Endpoint →
  //    省略の順。`aud` は Credential Issuer Identifier（OID4VCI 1.0 §8.2.1.1）。
  const proofJwt = generateProofJWT(
    {
      nonce: await resolveProofNonce(
        token.cNonce,
        ownProperty<string>(endpoints, 'nonceEndpoint'),
        resolved.fetchImpl,
      ),
      audience: opts.credentialIssuer,
      issuer: resolved.holderDid,
      keyId: resolved.keyId,
    },
    resolved.signer,
  );

  // 9. VC 受領。deferred はそのまま返す（判断は呼び出し側）。
  //    DPoP proof は `token_type` が `DPoP` のときだけ、`htu` = Credential Endpoint・`ath` 用に
  //    access_token を渡して生成する（PAR / Token の proof は再利用できない）。
  //    Bearer 束縛のトークンに `Authorization: DPoP` を付けると Issuer が拒否する。
  //    `tokenType` を渡すことで、proof 生成関数が未注入なのに DPoP 束縛トークンが返った場合を
  //    `requestCredential` 側が fail-closed で落とせる。
  const credentialDpop = credentialRequestDpop(
    token.tokenType,
    token.accessToken,
    endpoints.credentialEndpoint,
    resolved.createDpopProof,
  );
  return requestCredential({
    credentialEndpoint: endpoints.credentialEndpoint,
    accessToken: token.accessToken,
    format: opts.format,
    credentialDefinition: opts.credentialDefinition,
    vct: opts.vct,
    credentialConfigurationId: opts.credentialConfigurationId,
    proofJwt,
    // 値が undefined でも own プロパティとして載せ、下流の own 限定読みを無効化しない。
    dpop: credentialDpop,
    rebuildDpop: dpopProofRebuilder(resolved.createDpopProof, endpoints.credentialEndpoint, {
      accessToken: token.accessToken,
    }),
    tokenType: token.tokenType,
    correlationContext: resolved.correlationContext,
    fetchImpl: resolved.fetchImpl,
  });
}
