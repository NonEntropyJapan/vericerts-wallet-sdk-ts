/**
 * OID4VCI（OpenID for Verifiable Credential Issuance）の Proof 生成・VC 受信プリミティブ。
 *
 * 本モジュールは Pre-Authorized Code Flow のうち以下を担う:
 *
 * - `generateProofJWT`: c_nonce にバインドした JWT Proof（`openid4vci-proof+jwt`）を生成する。
 * - `requestCredential`: Credential Endpoint を呼び出し、受信した VC 文字列を取り出す。
 *
 * Token Request・Offer URI パース・Issuer Metadata 取得は別モジュール。`requestCredential` は呼び出し側が
 * 取得済みの `accessToken` / `cNonce` を受け取る。受信 VC の署名検証・永続化は呼び出し側の責務。
 *
 * JWT ライブラリ（`jose` 等）は導入せず、`issue.ts` と同じく `CredentialSigner` で署名しコンパクト JWS を
 * 自前で組み立てる。Credential 応答 JSON の検証・正規化は `oid4vci-credential-response.ts` に分離する。
 *
 * セキュリティ上の注意:
 * - 例外メッセージや `context` に privateKey・access_token・VC 本文・proof JWT を含めない。
 */

import { base64urlnopad } from '@scure/base';
import { base64urlText } from '../../base64url.js';
import type { CredentialSigner } from '../../credential/vc/signer.js';
import { ErrorCodes, VericertsError } from '../../errors.js';
import { type FetchLike, resolveInjectedFetch } from '../../fetch-di.js';
import { discardBody } from '../../http/body-limit.js';
import { isPublicHttpsUrl, isRedirectedResponse } from '../../http/public-https-url.js';
import type { CorrelationContext } from '../../observability/correlation.js';
import { correlationHeaders, readCorrelationContext } from '../../observability/correlation.js';
import { assertEpochSeconds } from '../../primitives/option-guard.js';
import { isNonBlankString } from '../../prototype-safety/non-empty-string.js';
import { ownProperty } from '../../prototype-safety/own-property.js';
import type { DpopProof } from '../dpop/dpop-common.js';
import { buildCredentialRequestBody } from './credential-wire/request-body.js';
import type { RequestCredentialResult } from './credential-wire/request-result.js';
import type { DpopProofRebuilder } from './dpop-nonce/index.js';
import { readDpopRebuilder, sendWithDpopNonceRetry } from './dpop-nonce/index.js';
import { resolveCredentialAuthHeaders } from './oid4vci-credential-auth.js';
import { type CredentialResponse, readCredentialResponse } from './oid4vci-credential-response.js';

export type {
  DeferredCredential,
  ReceivedCredential,
  RequestCredentialResult,
} from './credential-wire/request-result.js';
// 応答型は公開 API（`exports/auth.ts`）の一部なので、パース層へ移したあとも本モジュールから
// 引き続き公開する。
export type { CredentialResponse };

/** VC 受信のための HTTP タイムアウト（ミリ秒）。発行者通信は他メソッドと揃えて 10 秒。 */
const CREDENTIAL_REQUEST_TIMEOUT_MS = 10_000;

/** JWT Proof のヘッダ `typ`（OID4VCI 1.0 で固定）。 */
const PROOF_JWT_TYP = 'openid4vci-proof+jwt';

/** Credential Proof の `proof_type`（本 SDK は JWT Proof のみ対応）。 */
const PROOF_TYPE_JWT = 'jwt';

/** `requestCredential` が必要とする最小限の `fetch` シグネチャ（実体は `internal/fetch-di.ts`）。 */
export type { FetchLike } from '../../fetch-di.js';

/**
 * VC の type 列を表す Credential Definition。
 */
export interface CredentialDefinition {
  /** VC の type 配列（例: `["VerifiableCredential", "UniversityDegree"]`）。 */
  readonly type: readonly string[];
  /** メソッド固有の追加プロパティ（`@context` 等）。 */
  readonly [key: string]: unknown;
}

/** Credential Request に同梱する Holder Proof。 */
export interface CredentialProof {
  /** Proof 種別（本 SDK は `jwt` 固定）。 */
  readonly proof_type: typeof PROOF_TYPE_JWT;
  /** JWT Proof 文字列（`generateProofJWT` の戻り値）。 */
  readonly jwt: string;
}

/**
 * `generateProofJWT` のオプション。
 *
 * spec の `generateProofJWT(nonce, audience, signerKeyID)` を踏襲しつつ、payload の `iss`（Holder DID）
 * と header の `kid`（検証鍵 ID）を明示的に分けて受け取る。`kid` は `did#fragment` 形式の検証鍵 ID、
 * `issuer` はその DID 部分（`#fragment` を除いた DID）に対応する。脆い文字列分解を避けるため両者を
 * 明示入力とする。
 */
export interface GenerateProofJwtOptions {
  /** Proof の `nonce`（Nonce Endpoint か旧 Draft の `c_nonce`）。nonce を要求しない Issuer には省略する。 */
  readonly nonce?: string;
  /** Proof の `aud`。Credential Issuer Identifier であり Credential Endpoint URL ではない（OID4VCI 1.0 §8.2.1.1）。 */
  readonly audience: string;
  /** Holder DID（Proof の `iss` クレーム）。 */
  readonly issuer: string;
  /** 検証鍵 ID（`did#fragment` 形式、JWS ヘッダの `kid`）。 */
  readonly keyId: string;
  /**
   * `iat` 算出に使う現在時刻（ミリ秒、テスト注入用）。省略時は `Date.now()`。
   */
  readonly now?: number;
}

/** `requestCredential` のオプション。 */
export interface RequestCredentialOptions {
  /** Credential Endpoint の URL（Issuer Metadata の `credential_endpoint`）。 */
  readonly credentialEndpoint: string;
  /** Token Response で取得した access_token（`Authorization: Bearer`）。 */
  readonly accessToken: string;
  /** 要求するフォーマット（例: `jwt_vc_json` / `dc+sd-jwt`（新識別子）/ `vc+sd-jwt`（移行期間の旧識別子））。 */
  readonly format: string;
  /** 要求する VC の Credential Definition（SD-JWT VC では送らない。{@link RequestCredentialOptions.vct} を使う）。 */
  readonly credentialDefinition: CredentialDefinition;
  /**
   * SD-JWT VC の型識別子。`format` が SD-JWT VC のときだけ使い、`credential_definition` の代わりに
   * 送る（旧 Draft 形。draft-13 Annex A.3。1.0 Final の要求に `vct` は無い。根拠は `credential-wire/request-body.ts`）。
   */
  readonly vct?: string;
  /** `generateProofJWT` で生成した JWT Proof 文字列。 */
  readonly proofJwt: string;
  /** 指定すると OID4VCI 1.0 Final 形 `{ credential_configuration_id, proofs }` で送る（`credential-wire/request-body.ts`）。 */
  readonly credentialConfigurationId?: string;
  /**
   * Credential Endpoint 用の DPoP proof JWT（RFC 9449 §5）。
   *
   * 指定すると `Authorization: DPoP <access_token>` + `DPoP: <proof>` で送る。省略時は従来どおり
   * `Authorization: Bearer <access_token>`。proof は送信先 URL（`htu`）に束縛されるため、
   * ここに渡す proof は **`credentialEndpoint` を `htu` として生成**したものでなければならない
   * （PAR / Token Endpoint 用の proof を再利用すると Issuer が束縛検証で拒否する）。
   */
  readonly dpop?: DpopProof;
  /** `use_dpop_nonce`（RFC 9449 §9）を受けたときの nonce 付き proof 再生成関数（access_token の `ath` 込み）。1 回だけ再送する。 */
  readonly rebuildDpop?: DpopProofRebuilder;
  /**
   * Token Response の `token_type`（`TokenResponse.tokenType`）。
   *
   * `DPoP`（大文字小文字は区別しない）のときに `dpop` が無い場合は **fail-closed** で拒否する。
   * DPoP 束縛トークンを `Authorization: Bearer` で送っても RFC 9449 §7.1 準拠の Issuer が
   * 拒否するだけであり、SDK 側で落とせば access_token を平文で 1 度も送らずに済む。
   * 省略時はこの検査を行わない（`dpop` の有無だけで送出形式を決める）。
   */
  readonly tokenType?: string;
  /**
   * 1 回のユーザー操作に紐づく相関 ID。指定すると `traceparent` /
   * `X-Request-Id` ヘッダで Issuer へ伝播する。同じ受領フローの PAR / Token Request
   * （`PARRequest` / `*TokenRequest` の `correlationContext`）と**同じ値**を渡すこと。
   * 未指定ならヘッダ自体を出さない。
   */
  readonly correlationContext?: CorrelationContext;
  /**
   * HTTP リクエストに使う `fetch` 実装（テスト注入用）。省略時はグローバル `fetch`。
   */
  readonly fetchImpl?: FetchLike;
}

/**
 * c_nonce にバインドした OID4VCI JWT Proof（`openid4vci-proof+jwt`）を生成する。
 *
 * - header: `{ typ: 'openid4vci-proof+jwt', alg, kid }`
 * - payload: `{ iss, aud, iat, nonce? }`（`nonce` は Issuer が要求する場合のみ）
 *
 * 署名鍵は `CredentialSigner`（`credential/signer.ts`）で DI する。`issue.ts` と同じく
 * signing-input（`base64url(header).base64url(payload)`）を signer に署名させ、コンパクト JWS を
 * 組み立てる。生 privateKey は本関数に渡さない。
 *
 * @param options nonce / audience / issuer（Holder DID）/ keyId（kid）/ now。
 * @param signer JWT Proof 署名鍵（alg / sign を提供）。
 * @returns コンパクト JWT Proof 文字列（`header.payload.signature`）。
 * @throws nonce（指定時）/ audience / issuer / keyId が空の場合（VericertsError、code `3081`）、
 *         signer の署名演算が失敗した場合（code `1020`、signer 側）。
 */
export function generateProofJWT(
  options: GenerateProofJwtOptions,
  signer: CredentialSigner,
): string {
  // 分割代入はプロトタイプ鎖を辿る。これらは**署名済み proof JWT** にそのまま載るため、
  // 渡し忘れた JS 呼び出しで汚染値が 3081 のガードを素通りする。特に `keyId` は `kid` になり、
  // 検証側の鍵解決を攻撃者の指す鍵へ誘導する。
  const nonce = ownProperty<string>(options, 'nonce');
  const audience = ownProperty<string>(options, 'audience');
  const issuer = ownProperty<string>(options, 'issuer');
  const keyId = ownProperty<string>(options, 'keyId');
  // 必須クレームが空だと検証側で proof 不一致（3081）に倒れるため生成時点で弾く（`nonce` は省略可）。
  // 入力値は漏えい面を最小化するため message に含めない。
  if (
    (nonce !== undefined && !isNonBlankString(nonce)) ||
    !isNonBlankString(audience) ||
    !isNonBlankString(issuer) ||
    !isNonBlankString(keyId)
  ) {
    throw new VericertsError(ErrorCodes.HOLDER_PROOF_INVALID);
  }

  const nowMs = ownProperty<number>(options, 'now') ?? Date.now();
  // 非有限・負値・文字列の `now` は `iat: null` 等の proof を署名する。
  const iat = assertEpochSeconds(
    typeof nowMs === 'number' ? Math.floor(nowMs / 1000) : nowMs,
    ErrorCodes.HOLDER_PROOF_INVALID,
  );
  const header = { typ: PROOF_JWT_TYP, alg: signer.alg, kid: keyId };
  const payload = { iss: issuer, aud: audience, iat, ...(nonce === undefined ? {} : { nonce }) };

  const headerSeg = base64urlText(JSON.stringify(header));
  const payloadSeg = base64urlText(JSON.stringify(payload));
  const signingInput = `${headerSeg}.${payloadSeg}`;
  const signature = signer.sign(new TextEncoder().encode(signingInput));
  return `${signingInput}.${base64urlnopad.encode(signature)}`;
}

/**
 * Credential Endpoint を呼び出し、VC を受信する。
 *
 * 手順:
 * 0. `credentialEndpoint` が HTTPS でない（または URL 不正）なら access_token 漏えいを防ぐため
 *    `CREDENTIAL_REQUEST_FAILED`（8020）で拒否する。
 * 1. `dpop` 未指定かつ `tokenType` が `DPoP` なら、DPoP 束縛トークンを Bearer で送らずに
 *    `CREDENTIAL_REQUEST_FAILED`（8020、`reason: 'dpop_proof_required'`）で拒否する（fail-closed）。
 * 2. `POST <credentialEndpoint>`（`dpop` 指定時は `Authorization: DPoP <access_token>` +
 *    `DPoP: <proof>`、未指定時は `Authorization: Bearer <access_token>`、
 *    body = 旧 Draft 形 `{ format, credential_definition, proof }`（SD-JWT VC で `vct` 指定時は
 *    `credential_definition` に代えて `vct`）、または
 *    `credentialConfigurationId` 指定時は 1.0 形 `{ credential_configuration_id, proofs: { jwt: [jwt] } }`）。
 * 3. ネットワークエラー / タイムアウトは `ISSUER_COMMUNICATION_FAILED`（3004、再試行可）。
 * 4. HTTP 2xx 以外 / JSON 不正 / `credential` も `transaction_id` も無い応答は
 *    `CREDENTIAL_REQUEST_FAILED`（8020）。
 * 5. `credential`（旧 Draft）または `credentials: [{ credential }]`（1.0 §8.3。ちょうど 1 要素）があれば
 *    `{ status: 'issued', credential, cNonce }` を返す
 *    （署名検証・永続化は呼び出し側）。
 * 6. `credential` が無く `transaction_id` があれば遅延発行として
 *    `{ status: 'deferred', transactionId, cNonce }` を返す。
 *
 * @param options Credential Endpoint / access_token / format / definition / proofJwt /
 *                dpop / tokenType。
 * @returns 即時受信 VC または遅延発行の取引 ID。
 * @throws 通信失敗（code `3004`）・応答不正 / VC 取得失敗 / DPoP proof 欠落（code `8020`）の
 *         場合（VericertsError）。
 */
export async function requestCredential(
  options: RequestCredentialOptions,
): Promise<RequestCredentialResult> {
  const { credentialEndpoint, accessToken, format, credentialDefinition, proofJwt } = options;
  // `fetchImpl` は分割代入（＝鎖読み）で取り出さない。汚染下では DI を**省略した**正当な
  // 呼び出しが攻撃者の関数へ委譲され、Bearer access_token ごと渡ったうえ受領する VC を
  // 攻撃者が選べる。読み分けとレシーバ束ね直しの根拠は `internal/fetch-di.ts`。
  const { doFetch, receiver } = resolveInjectedFetch(options);

  // `Authorization` / `DPoP` ヘッダの決定（own 限定読み・空 proof の拒否・DPoP 束縛トークンの
  // fail-closed）は `oid4vci-credential-auth.ts` に集約する。
  const authHeaders = resolveCredentialAuthHeaders(options, accessToken);
  // 相関 ID も純データなので own 限定で 1 回だけ読む。形が壊れていれば未指定として扱う。
  const correlationContext = readCorrelationContext(options);

  // access_token（Bearer）を平文で送らないため、HTTPS 以外のエンドポイントは拒否する
  // （did:web 解決と同じく cleartext での秘匿情報漏えいを防ぐ）。URL として不正な場合も拒否。
  if (!isPublicHttpsUrl(credentialEndpoint)) {
    throw new VericertsError(ErrorCodes.CREDENTIAL_REQUEST_FAILED);
  }

  const body = buildCredentialRequestBody(options, { format, credentialDefinition, proofJwt });

  const controller = new AbortController();
  // 本文の読み出しまでを 1 つのタイムアウトで覆う（`clearTimeout` は本文読了後）。ヘッダだけ先に
  // 返して本文を引き延ばす Issuer に無限に待たないため（`internal/http/fetch-json.ts` の不変条件）。
  const timer = setTimeout(() => controller.abort(), CREDENTIAL_REQUEST_TIMEOUT_MS);
  // 読まずに失敗へ倒す経路でも本文を解放できるよう、`finally` から見える位置で宣言する。
  let response: Response | undefined;
  try {
    try {
      // `use_dpop_nonce`（RFC 9449 §9）なら nonce 付き proof で 1 回だけ再送。fetch は取り出し元をレシーバに束ねて呼ぶ。
      response = await sendWithDpopNonceRetry(
        (dpopProof) =>
          doFetch.call(receiver, credentialEndpoint, {
            method: 'POST',
            headers: {
              ...authHeaders,
              ...(dpopProof === undefined ? {} : { DPoP: dpopProof }),
              'Content-Type': 'application/json',
              Accept: 'application/json',
              // 相関 ID を指定したときだけヘッダを送る。
              ...correlationHeaders(correlationContext),
            },
            body,
            redirect: 'manual', // 3xx に追従して access_token / DPoP を別ホストへ再送しない
            signal: controller.signal,
          }),
        ownProperty<string>(authHeaders, 'DPoP'),
        readDpopRebuilder(options),
      );
    } catch {
      // ネットワークエラー / タイムアウト（abort）。詳細は秘密を含み得るため正規化する。
      throw new VericertsError(ErrorCodes.ISSUER_COMMUNICATION_FAILED);
    }
    if (!response.ok || isRedirectedResponse(response)) {
      // HTTP エラー（invalid_proof / invalid_grant / authorization_pending 等）・リダイレクト。
      throw new VericertsError(ErrorCodes.CREDENTIAL_REQUEST_FAILED);
    }

    // 本文読み出しもタイムアウトと例外正規化の内側に置く（`oid4vci-credential-response.ts`）。
    const parsed = await readCredentialResponse(response);

    // `parseCredentialResponse` は 3 キーを（欠落時も）必ず**自身のプロパティ**として定義するため、
    // 以下の読みは汚染された `Object.prototype` へ到達しない（own 化を repack で無効化しない）。
    if (parsed.credential !== undefined) {
      return { status: 'issued', credential: parsed.credential, cNonce: parsed.c_nonce };
    }
    if (parsed.transaction_id !== undefined) {
      return { status: 'deferred', transactionId: parsed.transaction_id, cNonce: parsed.c_nonce };
    }
    // credential も transaction_id も無い応答は VC を取り出せないため失敗扱い。
    throw new VericertsError(ErrorCodes.CREDENTIAL_REQUEST_FAILED);
  } finally {
    clearTimeout(timer);
    // 本文を読まずに throw した経路が接続を掴んだまま残らないようにする（読了後は no-op）。
    discardBody(response);
  }
}
