/**
 * ファサード `receiveCredential` の入出力型。
 *
 * `ReceivedVerifiableCredential` は SD-JWT VC または JWT-VC の受領結果を表し、
 * `claims` のほかに元の `raw` と `format` を持つ。W3C VC Data Model の JSON-LD 文書は
 * `VerifiableCredential`（`@context` / `credentialSubject` を持つ）で表す。
 */

import type { CredentialSigner } from '../../../credential/vc/signer.js';
import type { FetchLike } from '../../../fetch-di.js';
import type { VCFormat } from '../../../issuer/module/issue-options.js';
import type { CorrelationContext } from '../../../observability/correlation.js';
import type { AuthorizationRedirect } from '../authz-flow/types.js';
import type { DpopProofFactory } from '../oid4vci-credential-dpop.js';

/**
 * 受領した VC の直列化形式。
 *
 * 発行時の `IssueOptions.format` と受領結果が共有する型。定義は
 * `issuer/module/issue-options.ts` から再エクスポートする。
 *
 * 公開元も 1 つに保つ（メインバレルの `exports/issuer.ts` のみ。`exports/experimental.ts` からは
 * 出さない）。
 */
export type { VCFormat };

/**
 * ファサード `receiveCredential` が返す受領結果。
 *
 * `raw` に受領したバイト列をそのまま保持する。**署名検証は本型を作る段では行わない**
 * （`deps.verifyReceived` を渡した場合のみ実行する。既定は呼び出し側の責務で、
 * `requestCredential` / `receivePIDCredential` と同じ契約）。
 *
 * @experimental 挙動・シグネチャが変わることがある（v1.0 で `@stable` 昇格予定）。
 */
export interface ReceivedVerifiableCredential {
  /**
   * VC の識別子（`jti`、または JWT-VC の `vc.id`）。
   *
   * **告知されないことがある。** SD-JWT VC（HAIP の既定フォーマット）は識別子クレームを必須と
   * せず、W3C VC Data Model v2 も `id` を任意と定める。受領できた VC を識別子が無いだけで
   * 捨てるのは受領の失敗として不適切なので、無い場合は本メンバを省く。
   */
  readonly id?: string;
  /** VC の型列（SD-JWT VC は `[vct]`、JWT-VC は `vc.type`）。 */
  readonly type: readonly string[];
  /** 発行者の識別子（`iss`）。 */
  readonly issuer: string;
  /** 発行日時（`iat` / `nbf` を ISO 8601 へ写したもの）。 */
  readonly issuanceDate: string;
  /** 失効日時（`exp` を ISO 8601 へ写したもの）。告知が無ければ省く。 */
  readonly expirationDate?: string;
  /** 構造クレームを除いた属性集合（`null` プロトタイプ）。 */
  readonly claims: Record<string, unknown>;
  /** 受領した生の VC 文字列（署名検証・永続化に用いる）。 */
  readonly raw: string;
  /** 直列化形式。 */
  readonly format: VCFormat;
}

/**
 * ファサード `receiveCredential` の依存。
 *
 * 文字列や相関 ID などのデータは自身のプロパティから読み取る。関数値は
 * プロトタイプメソッドも採用する（`nonObjectPrototypeProperty`）。`Object.prototype` 由来（汚染）の値は
 * 全 15 キーについて `8010` で拒否する（`rejectPollutedReceiveDeps`）。`facade/deps.ts` に集約する。
 *
 * @experimental 挙動・シグネチャが変わることがある（v1.0 で `@stable` 昇格予定）。
 */
export interface ReceiveCredentialDeps {
  /** JWT Proof の署名鍵（生 privateKey は渡さない）。 */
  readonly signer: CredentialSigner;
  /** Holder DID（JWT Proof の `iss`）。 */
  readonly holderDid: string;
  /** 検証鍵 ID（JWT Proof の `kid`、`did#fragment` 形式）。 */
  readonly keyId: string;
  /**
   * 認可 URL を開いて `code` / `state` / `iss` を受領する関数。`iss`（RFC 9207）は AS Metadata の `issuer` と完全一致が必須で、欠落・不一致は Token Request 前に拒否される。
   *
   * **`authorization_code` grant の Offer では必須。** 未指定は「認可をスキップする」ではなく
   * fail-closed に倒す（`8010`）。`pre-authorized_code` grant のみの Offer では不要。
   */
  readonly authorize?: (authorizationUrl: string) => Promise<AuthorizationRedirect>;
  /** Offer の `tx_code` が要求する PIN。pre-authorized_code 経路でのみ使う。 */
  readonly txCode?: string;
  /** `<WUA>~<WUA-PoP>` 形式の client assertion。PAR / Token の両方へ載る。 */
  readonly clientAssertion?: string;
  /** `clientAssertion` 指定時に必須の `client_assertion_type`（RFC 7521 §4.2）。 */
  readonly clientAssertionType?: string;
  /** PAR に載せる `client_id`。`authorization_code` grant では必須。 */
  readonly clientId?: string;
  /** 認可のコールバック先。`authorization_code` grant では必須。 */
  readonly redirectUri?: string;
  /** 要求フォーマット。省略時は SD-JWT VC（`dc+sd-jwt`。HAIP の既定）。 */
  readonly format?: string;
  /**
   * Credential Request の本文の形。省略時は `draft`（旧 Draft 形:
   * `format` + `credential_definition` + `proof`）。`1.0` を指定すると OID4VCI 1.0 Final §8.2 の
   * `{ credential_configuration_id, proofs: { jwt: [..] } }` で送る（`credential_configuration_id` は Offer の
   * `credential_configuration_ids[0]`）。**SDK は Issuer のバージョンを推測しない**ので、1.0 Final の
   * Issuer にはここで明示する。`credential_identifiers`（Token Response の `authorization_details`）を
   * 返す AS 向けの `credential_identifier` 形は未対応（Planned）。
   */
  readonly credentialRequestVersion?: 'draft' | '1.0';
  /**
   * `htu` ごとの DPoP proof 生成（RFC 9449 §4.3）。
   *
   * Credential Endpoint 用の呼び出し（`token_type: "DPoP"` のときだけ）には第 2 引数
   * `ctx.accessToken` が渡る。保護リソースへ提示する proof は `ath`（access_token の
   * SHA-256）を含む必要があるため、実装は `createDpopProof({ htm: 'POST', htu, accessToken }, signer)`
   * へ中継すること（RFC 9449 §4.2 / §7.1）。PAR / Token 用は `htu` のみで呼ばれる。
   * 宛先が `use_dpop_nonce`（`DPoP-Nonce`）で拒否したときは、同じ引数に `ctx.nonce` を加えて**1 回だけ**
   * 再度呼ばれる（RFC 9449 §8 / §9。実装は `nonce` を proof へ中継すること）。
   */
  readonly createDpopProof?: DpopProofFactory;
  /**
   * 受領した VC の署名検証フック。
   *
   * 指定した場合、`raw` を渡して呼び出し、署名不一致相当の throw を `3010`（`SIG_INVALID`）へ正規化する
   * （`3010` 以外の `VericertsError` は元のコードのまま。フックは VC 本文・署名を例外に載せないこと）。**未指定なら署名検証を行わない** — Issuer 鍵の解決
   * （DID 解決 / `x5c` / Trust Anchor）は本モジュールが持たない依存であり、既存の受領経路
   * （`requestCredential` / `receivePIDCredential`）も一貫して呼び出し側の責務としている。
   */
  readonly verifyReceived?: (raw: string) => void | Promise<void>;
  /**
   * 1 回のユーザー操作に紐づく相関 ID。
   *
   * 指定すると、この受領で外へ出る PAR / Token / Credential Request のすべてに同じ
   * `traceparent` / `X-Request-Id` が載る（1 回の受領操作 = 1 本のトレース）。上流
   * （Popup / Background SW）が発行済みの ID は `createCorrelationContext` で組み立てて渡す。
   * 未指定なら相関ヘッダを出さない。
   */
  readonly correlationContext?: CorrelationContext;
  /** HTTP 差し替えシーム（テスト注入用）。省略時はグローバル `fetch`。 */
  readonly fetchImpl?: FetchLike;
}
