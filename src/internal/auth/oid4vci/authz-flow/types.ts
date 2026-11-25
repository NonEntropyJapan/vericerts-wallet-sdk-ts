/**
 * OID4VCI Authorization Code Flow（PAR + PKCE）オーケストレーションの入力型。
 *
 * このフローは 4 つのエンドポイント（PAR / Authorization / Token / Credential）と、その途中に
 * 挟まる**ブラウザ / Custom Tab でのユーザー認可**から成る。エンドポイント群は「どこと話すか」、
 * `AuthorizationCodeFlowDeps` は「誰が署名し・誰がブラウザを開き・どう HTTP を出すか」で分ける。
 *
 * セキュリティ上の注意:
 * - 本型のフィールドは**分割代入で読まない**。`signer` / `authorize` / `fetchImpl` /
 *   `createDpopProof` は class の prototype メソッドとして実装され得るため
 *   `nonObjectPrototypeProperty`、純データは `ownProperty` で読む（`deps.ts` に集約）。
 * - 呼び出し側が渡すオブジェクトは `JSON.parse` を通らないため `parse-json.ts` のパース境界が
 *   一切効かない。読み取り時点の判定が唯一の防御線である。
 */

import type { CredentialSigner } from '../../../credential/vc/signer.js';
import type { FetchLike } from '../../../fetch-di.js';
import type { CorrelationContext } from '../../../observability/correlation.js';
import type { CredentialDefinition } from '../oid4vci.js';
import type { DpopProofFactory } from '../oid4vci-credential-dpop.js';
import type { OAuth2AuthzDetails } from '../par/index.js';

/**
 * Authorization Code Flow が使う 4 つのエンドポイント。
 *
 * すべて HTTPS を必須とする（`client_assertion` / 認可コード / access_token / JWT Proof が
 * 平文で流れる経路を作らないため）。**検査は本フローが 4 つとも入口で行う**
 * （`options.ts` の `resolveEndpoints`。非 HTTPS は fetch を発生させずに `8010`
 * （`context.reason: 'non_https_endpoint'`）で拒否する）。下流プリミティブの HTTPS 検査は
 * そのまま残るが、`requestTokenAuthorizationCode` のそれは `clientAssertion` 指定時のみの
 * 条件付きであり後方互換のため無条件化できないため、**下流に委譲するだけでは本不変条件は
 * 成立しない**。下流の検査は多層防御として扱う。
 *
 * @experimental 挙動・シグネチャが変わることがある（v1.0 で `@stable` 昇格予定）。
 */
export interface AuthorizationCodeEndpoints {
  /** AS の `pushed_authorization_request_endpoint`。 */
  readonly parEndpoint: string;
  /** AS の Authorization Endpoint（ブラウザで開く URL の基底）。 */
  readonly authorizationEndpoint: string;
  /** AS の Token Endpoint。 */
  readonly tokenEndpoint: string;
  /** Issuer の Credential Endpoint。 */
  readonly credentialEndpoint: string;
  /**
   * Issuer Metadata の `nonce_endpoint`（OID4VCI 1.0 §7。任意）。Token Response に `c_nonce` が無いとき、
   * JWT Proof の `nonce` をここから取得する。HTTPS・公開ホストのみ。
   */
  readonly nonceEndpoint?: string;
}

/**
 * 認可後のリダイレクトで受領した値。
 *
 * `state` は PAR で push した値と**完全一致**しなければならない（CSRF 防止）。照合は
 * フロー側が行うため、`authorize` の実装は受け取った値をそのまま返せばよい（自前で照合して
 * 良し悪しを判断する必要はない）。
 *
 * @experimental 挙動・シグネチャが変わることがある（v1.0 で `@stable` 昇格予定）。
 */
export interface AuthorizationRedirect {
  /** 認可コード（`code`）。 */
  readonly code: string;
  /** リダイレクトで返された `state`。 */
  readonly state: string;
  /**
   * 認可応答の `iss`（RFC 9207）。認可サーバーが返した値をそのまま載せる（未返却なら省略）。
   *
   * フローは AS Metadata の `issuer`（`AuthorizationCodeFlowOptions.authorizationServerIssuer`）との
   * **完全一致**を要求し、欠落・不一致は Token Request の前に拒否する（AS mix-up 対策。RFC 9700 §4.4）。
   * `iss` を返さない AS は本フローでは利用できない（fail-closed）。
   */
  readonly iss?: string;
}

/**
 * Authorization Code Flow で受領する VC の要求内容。
 *
 * @experimental 挙動・シグネチャが変わることがある（v1.0 で `@stable` 昇格予定）。
 */
export interface AuthorizationCodeFlowOptions {
  /** 4 つのエンドポイント。 */
  readonly endpoints: AuthorizationCodeEndpoints;
  /**
   * Credential Issuer Identifier（Offer / Issuer Metadata の `credential_issuer`）。JWT Proof の
   * `aud` になる（OID4VCI 1.0 §8.2.1.1。Credential Endpoint の URL ではない）。
   */
  readonly credentialIssuer: string;
  /**
   * 認可コードの発行元として期待する AS の識別子（AS Metadata の `issuer`）。認可応答の `iss` と
   * **完全一致**しなければ Token Request を送らない（RFC 9207 / RFC 9700 §4.4）。
   * ファサードは取得した AS Metadata の `issuer` を渡す。
   */
  readonly authorizationServerIssuer: string;
  /** Wallet の client_id（AS 登録済み）。PAR / 認可 URL / Token Request で同一の値を使う。 */
  readonly clientId: string;
  /** 認可後のコールバック先（カスタムスキーム等）。AS 登録済み URI と一致させる。 */
  readonly redirectUri: string;
  /** 要求するフォーマット（例: `dc+sd-jwt` / `jwt_vc_json`）。 */
  readonly format: string;
  /** 要求する VC の Credential Definition（SD-JWT VC では {@link AuthorizationCodeFlowOptions.vct} を使う）。 */
  readonly credentialDefinition: CredentialDefinition;
  /**
   * SD-JWT VC の型識別子（`RequestCredentialOptions.vct`）。
   *
   * `format` が SD-JWT VC のとき、Credential Request は `credential_definition` ではなく `vct` で
   * 要求する VC の型を伝える（旧 Draft 形。draft-13 Annex A.3。1.0 Final の要求に `vct` は無い）。
   */
  readonly vct?: string;
  /**
   * 指定すると Credential Request を OID4VCI 1.0 Final 形（`credential_configuration_id` + `proofs`）で送る
   * （`RequestCredentialOptions.credentialConfigurationId`）。省略時は旧 Draft 形。
   */
  readonly credentialConfigurationId?: string;
  /** 要求する credential_configuration_id（OAuth scope）。`authorizationDetails` と併用可。 */
  readonly scope?: string;
  /** OID4VCI `authorization_details`（`[{ type: "openid_credential", ... }]`、RFC 9396）。 */
  readonly authorizationDetails?: readonly OAuth2AuthzDetails[];
  /**
   * `client_assertion`。指定時は `clientAssertionType` も必須。
   *
   * Wallet Attestation を使う場合の値は `<WUA>~<WUA-PoP>`
   * （`buildClientAttestation` の `clientAssertion`）。SDK にとっては不透明な文字列で、
   * **PAR と Token Request の両方に同じ値を載せる**（RFC 9126 §2 が PAR のクライアント認証を
   * Token Endpoint と同一に扱うため）。
   *
   * WUA-PoP の `nonce` に AS の `c_nonce` を載せる運用は本フローのスコープ外である。
   * Authorization Code Flow では PAR が AS への最初の要求であり、その PAR 自身を認証する PoP に
   * 載せられる `c_nonce` は存在しない（pre-authorized_code フローと同じ制約。`c_nonce` の供給は
   * 呼び出し側の責務で、Nonce Endpoint を使う経路は `eudi/issuance/nonce.ts` にある）。
   */
  readonly clientAssertion?: string;
  /** `client_assertion_type`（RFC 7521 §4.2 が `client_assertion` 使用時に REQUIRED と定める）。 */
  readonly clientAssertionType?: string;
}

/**
 * Authorization Code Flow の依存（署名・ブラウザ起動・HTTP・DPoP）。
 *
 * @experimental 挙動・シグネチャが変わることがある（v1.0 で `@stable` 昇格予定）。
 */
export interface AuthorizationCodeFlowDeps {
  /**
   * JWT Proof（`openid4vci-proof+jwt`）の署名鍵。`generateProofJWT` が要求する
   * `CredentialSigner` と同一型で、生 privateKey は渡さない。
   */
  readonly signer: CredentialSigner;
  /** Holder DID。JWT Proof payload の `iss` になる。 */
  readonly holderDid: string;
  /** 検証鍵 ID（`did#fragment` 形式）。JWT Proof の JWS ヘッダ `kid` になる。 */
  readonly keyId: string;
  /**
   * 認可 URL をブラウザ / Custom Tab で開き、リダイレクトで返る `code` / `state` を受領する。
   *
   * **プラットフォーム層の責務なので DI する。** SDK は Chrome 拡張・モバイル・Node の
   * いずれでも動き、ブラウザの起動方法と Deep Link の受け口は実行環境ごとに違う。ここを
   * SDK が内蔵すると環境ごとの分岐を抱え込み、テストからも切り離せない。
   *
   * 引数は組み立て済みの認可 URL（`client_id` と `request_uri` のみを含む）。
   * ユーザーが拒否した / 期限切れた場合は例外を投げること（フローは `8010` へ正規化する）。
   */
  readonly authorize: (authorizationUrl: string) => Promise<AuthorizationRedirect>;
  /**
   * HTTP 呼び出しの差し替えシーム（PAR / Token / Credential の 3 経路すべてに伝播する）。
   * 省略時はグローバル `fetch`。
   */
  readonly fetchImpl?: FetchLike;
  /**
   * 1 回のユーザー操作に紐づく相関 ID。
   *
   * **フロー全体で 1 つの値を使う。** DPoP proof と違って送信先ごとに作り分けず、PAR / Token /
   * Credential の 3 経路すべてに同じ `traceparent` / `X-Request-Id` を載せる（要求ごとに作り直すと
   * 1 回の受領操作が別々のトレースに割れ、同じ操作として追跡できない）。したがって関数では
   * なく値で受け取る。未指定なら相関ヘッダを出さない。
   *
   * 上流（Popup / Background SW）が発行済みの ID を引き継ぐ場合は
   * `createCorrelationContext({ traceparent, requestId })` で組み立てた値を渡す。
   */
  readonly correlationContext?: CorrelationContext;
  /**
   * DPoP proof（RFC 9449）を生成する関数（HAIP では任意）。
   *
   * **proof ごとに `htu` が違うため、値ではなく関数で受け取る。** RFC 9449 §4.3 は proof を
   * 送信先 URL に束縛すると定めるため、送信先ごとに別々の proof が必要になる（1 つの値を
   * 複数の宛先へ載せると AS / Issuer が束縛検証で拒否する）。したがってフローは
   * **PAR / Token / Credential の 3 経路それぞれで 1 回ずつ**、`parEndpoint` /
   * `tokenEndpoint` / `credentialEndpoint` を `htu` として渡して呼ぶ（`receive.ts` の手順
   * 3 / 7 / 9）。
   *
   * 実装は `createDpopProof({ htm: 'POST', htu }, signer)`（`dpop/dpop.ts`）を使う。
   * 未指定なら DPoP ヘッダを送らない。
   *
   * **未指定なのに AS が DPoP 束縛トークン（`token_type: "DPoP"`）を返した場合は fail-closed。**
   * `requestCredential` が Credential Request を送らず `8020`（`reason: 'dpop_proof_required'`）で落とす
   * （`oid4vci-credential-auth.ts`）。DPoP 束縛の access_token を `Authorization: Bearer` で
   * 送っても RFC 9449 §7.1 準拠の Issuer が拒否するだけであり、平文で 1 度も送らない方が
   * 露出面が小さい。
   */
  readonly createDpopProof?: DpopProofFactory;
}
