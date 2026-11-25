/**
 * OID4VCI Token Endpoint クライアントのグラント種別定数とリクエスト型（Wallet 側）。
 *
 * 本モジュールは `oid4vci-token.ts` から、グラント種別定数と各グラントのリクエスト型
 * （`PreAuthorizedTokenRequest` / `AuthorizationCodeTokenRequest`）だけを切り出したものである。
 * 切り出しの契機は `.linterly.yml` の 1 ファイル 300 行上限だが、境界は行数ではなく責務で引いて
 * いる（型定義とその JSDoc は本モジュール、送信ロジックは `oid4vci-token.ts`）。
 * `oid4vci-token-http.ts`（HTTP 送信・応答正規化の切り出し）と同じ方針。
 */

import type { CorrelationContext } from '../../../observability/correlation.js';
import type { DpopProof } from '../../dpop/dpop-common.js';
import type { DpopProofRebuilder } from '../dpop-nonce/index.js';
import type { FetchLike } from '../oid4vci.js';

/** pre-authorized_code グラント種別の URN。 */
export const GRANT_TYPE_PRE_AUTHORIZED_CODE =
  'urn:ietf:params:oauth:grant-type:pre-authorized_code' as const;

/** authorization_code グラント種別。 */
export const GRANT_TYPE_AUTHORIZATION_CODE = 'authorization_code' as const;

/** pre-authorized_code グラントの Token Request パラメータ。 */
export interface PreAuthorizedTokenRequest {
  /** Credential Offer から取得した pre-authorized_code。 */
  readonly preAuthorizedCode: string;
  /**
   * tx_code（ユーザー入力 PIN）。Offer の `tx_code` が存在する場合は必須。
   * 不要な場合は省略する。
   */
  readonly txCode?: string;
  /**
   * `client_assertion`。AS が Attestation-Based Client Auth を要求する場合に指定する。
   *
   * Wallet Attestation を使う場合の値は WUA JWT と WUA-PoP JWT を `~` で連結した
   * `<WUA>~<WUA-PoP>` で、
   * `buildClientAttestation`（`internal/eudi/wua/proof.ts`）の `clientAssertion` がこの形を返す。
   * pre-authorized_code 経路と authorization_code 経路で形式の使い分けはしない。
   * SDK にとっては不透明な文字列であり、内容の検証・組み立て・分解は行わずそのまま送信する。
   */
  readonly clientAssertion?: string;
  /**
   * `client_assertion_type`（RFC 7521 §4.2 が `client_assertion` 使用時に REQUIRED と定める）。
   *
   * SDK は既定値を持たない。`clientAssertion` を指定する場合は本フィールドも必ず指定すること
   * （未指定・空文字・空白のみは送信前に 8010 で拒否する）。Wallet Attestation を使う場合の値は
   * 公開定数 `WUA_CLIENT_ASSERTION_TYPE`（`internal/eudi/wua/types.ts`）と同じ 1 値に確定している
   * それでも既定値を補完しないのは、`clientAssertion` が Wallet Attestation なのか
   * RFC 7523 の `jwt-bearer` assertion なのかを SDK からは判別できず、既定値を補うと別形式の
   * assertion を誤ってラベル付けして送信しうるため。`clientAssertion` が指定されている場合にのみ送信する。
   */
  readonly clientAssertionType?: string;
  /**
   * Token Endpoint に送る DPoP proof JWT（RFC 9449 §4.2）。
   *
   * **RFC 9449 はグラント種別を問わない。** §5 は「Token Endpoint への要求」に proof を添えると
   * 定めており、pre-authorized_code を除外していない。authorization_code 経路
   * （`AuthorizationCodeTokenRequest`）と PAR 経路（`PARRequest`）が既に `dpop` を持つのに本経路
   * だけ持たないと、DPoP を要求する Issuer の Offer が pre-authorized_code だった場合に
   * Wallet が DPoP 束縛の access_token を取得できず受領そのものが成立しない。
   *
   * 他のフィールドと異なり body には載らず `DPoP: <proof>` ヘッダとして送信される
   * （RFC 9449 §5 が proof を HTTP ヘッダで送ると定めるため）。呼び出し側が
   * `createDpopProof({ htm: 'POST', htu: <tokenEndpoint> }, signer)` で生成し、`htu` を
   * `tokenEndpoint` と一致させること（不一致だと AS が RFC 9449 §4.3 の HTTP 束縛検証で拒否する）。
   * 空文字・空白のみは送信前に 8010 で拒否する。**未指定時はヘッダ自体を出さない**ため、
   * `dpop` を渡さない既存の呼び出しの挙動は変わらない。
   */
  readonly dpop?: DpopProof;
  /**
   * `dpop` を載せた要求が `use_dpop_nonce`（400 + `DPoP-Nonce`。RFC 9449 §8）で拒否されたとき、その nonce 付き
   * proof を作り直す関数。**1 回だけ**再送する。`dpop` 未指定なら無効（Bearer 経路は変わらない）。
   */
  readonly rebuildDpop?: DpopProofRebuilder;
  /**
   * 1 回のユーザー操作に紐づく相関 ID。指定すると `traceparent` /
   * `X-Request-Id` ヘッダで Issuer へ伝播する。**1 つの受領フロー（PAR → Token → Credential）で
   * 同じ値を使う**こと（操作単位の識別子であり、要求ごとに作り直すと相関が切れる）。
   * 未指定ならヘッダ自体を出さない。ワイヤの body には載らないため camelCase。
   */
  readonly correlationContext?: CorrelationContext;
  /**
   * HTTP 呼び出しの差し替えシーム（Credential Endpoint 経路 `RequestCredentialOptions` /
   * PAR 経路 `PARRequest` と同じ役割・同じ解決規則）。ワイヤに乗らないため camelCase。
   * 省略時はグローバル `fetch` を使う。
   */
  readonly fetchImpl?: FetchLike;
}

/**
 * authorization_code グラントの Token Request パラメータ。
 *
 * 命名規約: 本型のフィールドは camelCase とし、SDK がワイヤの snake_case
 * （`code_verifier` / `redirect_uri` / `client_id` / `client_assertion` …）へマッピングする。
 * `PARRequest`（`par/par.ts`）が snake_case なのは RFC 9126 のワイヤパラメータ名を
 * そのまま型に写す別方針によるものであり、揺れではない。
 */
export interface AuthorizationCodeTokenRequest {
  /** 認可エンドポイントから受領した認可コード。 */
  readonly code: string;
  /** PKCE（RFC 7636, S256）の code_verifier。このフローで必須。 */
  readonly codeVerifier: string;
  /**
   * `redirect_uri`。認可リクエストで送った値と一致させる必要がある場合に指定する
   * （RFC 6749 §4.1.3）。
   */
  readonly redirectUri?: string;
  /** Wallet の client_id（AS が要求する場合）。 */
  readonly clientId?: string;
  /**
   * `client_assertion`。AS が Attestation-Based Client Auth を要求する場合に指定する。
   *
   * Wallet Attestation を使う場合の値は WUA JWT と WUA-PoP JWT を `~` で連結した
   * `<WUA>~<WUA-PoP>` で、
   * `buildClientAttestation`（`internal/eudi/wua/proof.ts`）の `clientAssertion` がこの形を返す。
   * PAR 経路と Token Request 経路で形式の使い分けはしない。
   * SDK にとっては不透明な文字列であり、内容の検証・組み立て・分解は行わずそのまま送信する。
   */
  readonly clientAssertion?: string;
  /**
   * `client_assertion_type`（RFC 7521 §4.2 が `client_assertion` 使用時に REQUIRED と定める）。
   *
   * SDK は既定値を持たない。`clientAssertion` を指定する場合は本フィールドも必ず指定すること
   * （未指定・空文字・空白のみは送信前に 8010 で拒否する）。Wallet Attestation を使う場合の値は
   * 公開定数 `WUA_CLIENT_ASSERTION_TYPE`（`internal/eudi/wua/types.ts`）と同じ 1 値に確定している
   * それでも既定値を補完しないのは、`clientAssertion` が Wallet Attestation なのか
   * RFC 7523 の `jwt-bearer` assertion なのかを SDK からは判別できず、既定値を補うと別形式の
   * assertion を誤ってラベル付けして送信しうるため。`clientAssertion` が指定されている場合にのみ送信する。
   */
  readonly clientAssertionType?: string;
  /**
   * Token Endpoint に送る DPoP proof JWT（RFC 9449 §4.2）。
   *
   * 他のフィールドと異なり body には載らず `DPoP: <proof>` ヘッダとして送信される
   * （RFC 9449 §5）。呼び出し側が
   * `createDpopProof({ htm: 'POST', htu: <tokenEndpoint> }, signer)` で生成し、`htu` を
   * `tokenEndpoint` と一致させること（不一致だと AS が RFC 9449 §4.3 の HTTP 束縛検証で拒否する）。
   * 空文字・空白のみは送信前に 8010 で拒否する。
   */
  readonly dpop?: DpopProof;
  /** `use_dpop_nonce` チャレンジ（RFC 9449 §8）時の nonce 付き proof 再生成関数。{@link PreAuthorizedTokenRequest.rebuildDpop} と同じ。 */
  readonly rebuildDpop?: DpopProofRebuilder;
  /**
   * 1 回のユーザー操作に紐づく相関 ID。PAR 経路
   * （`PARRequest.correlationContext`）/ Credential Endpoint 経路と**同じ値**を渡すことで、
   * 1 回の受領フローが 1 本のトレースに繋がる。未指定ならヘッダ自体を出さない。
   */
  readonly correlationContext?: CorrelationContext;
  /**
   * HTTP 呼び出しの差し替えシーム（Credential Endpoint 経路 `RequestCredentialOptions` /
   * PAR 経路 `PARRequest` と同じ役割・同じ解決規則）。ワイヤに乗らないため camelCase。
   * 省略時はグローバル `fetch` を使う。
   */
  readonly fetchImpl?: FetchLike;
}
