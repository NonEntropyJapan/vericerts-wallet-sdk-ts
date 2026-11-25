/**
 * OAuth 2.0 Authorization Server Metadata 取得（`.well-known/oauth-authorization-server`）。
 *
 * RFC 8414 §3 の AS Metadata から認可エンドポイント、Token Endpoint と
 * `pushed_authorization_request_endpoint`（RFC 9126 §5）を取得する。
 *
 * Credential Offer が示すのは `credential_issuer` だけで、Authorization Code Flow が必要とする
 * 4 エンドポイントのうち PAR と Authorization は Issuer Metadata にも載らない。Issuer Metadata の
 * `authorization_servers`（`eudi/issuance/metadata.ts`）で告知された AS の Metadata を引いて
 * はじめて解決できるため、その解決だけを本モジュールに切り出す。
 *
 * SDK の Authorization Code Flow は PAR（RFC 9126）を使う。PAR エンドポイントを
 * 告知しない AS ではフローを開始できない。
 *
 * セキュリティ上の注意:
 * - 取得と入口検査（HTTPS 限定・リダイレクト降格の拒否・本文読了までのタイムアウト・
 *   プロトタイプ除去）は `internal/auth/well-known-json/index.ts` と共有する。Issuer Metadata 取得と
 *   同一の攻撃面であり、検査を書き写すと片方だけが弱くなる。
 * - **発見した 3 つのエンドポイントも HTTPS を必須とする。** ここを緩めると、Metadata を
 *   すり替えられた時点で `client_assertion`（`<WUA>~<WUA-PoP>`）・認可コード・`code_verifier`・
 *   access_token が平文で攻撃者へ流れる。
 * - 例外の `context` には固定の識別子だけを載せ、URL・レスポンス本文・`cause` を一切含めない。
 */

import { ErrorCodes, VericertsError } from '../../errors.js';
import type { FetchLike } from '../../fetch-di.js';
import { isPublicHttpsUrl } from '../../http/public-https-url.js';
import { isNonBlankString } from '../../prototype-safety/non-empty-string.js';
import { ownProperty } from '../../prototype-safety/own-property.js';
import { fetchInsertedWellKnownJson } from '../well-known-json/index.js';
import { sameIdentifier } from './identifier/same-identifier.js';

/** AS Metadata の well-known パス（RFC 8414 §3。issuer の path 成分は host と path のあいだへ挿入する）。 */
const AS_METADATA_PATH = '/.well-known/oauth-authorization-server';

/**
 * AS Metadata から解決した Authorization Code Flow のエンドポイント組。
 *
 * @experimental 挙動・シグネチャが変わることがある（v1.0 で `@stable` 昇格予定）。
 */
export interface AuthorizationServerEndpoints {
  /** PAR エンドポイント（`pushed_authorization_request_endpoint`、HTTPS）。 */
  readonly parEndpoint: string;
  /** 認可エンドポイント（`authorization_endpoint`、HTTPS）。 */
  readonly authorizationEndpoint: string;
  /** Token エンドポイント（`token_endpoint`、HTTPS）。 */
  readonly tokenEndpoint: string;
  /**
   * AS Metadata の `issuer`（取得に用いた識別子との一致を検証済み）。認可応答の `iss`（RFC 9207）を
   * これと完全一致で照合する（AS mix-up 対策）。
   */
  readonly issuer: string;
}

/**
 * AS Metadata 取得の失敗を `ISSUER_COMMUNICATION_FAILED`（3004、再試行可）へ正規化する。
 *
 * Issuer Metadata 取得（`eudi/issuance/metadata.ts`）と同じコードへ寄せる。呼び出し側から見て
 * どちらも「発行者側の Metadata が引けなかった」であり、再試行可否も同じである。
 * `reason` は**固定の識別子のみ**。URL・レスポンス本文・JWT・`cause` は載せない。
 */
function asMetadataFailure(reason: string): VericertsError {
  return new VericertsError(ErrorCodes.ISSUER_COMMUNICATION_FAILED, { context: { reason } });
}

/**
 * 必須メンバを own 限定で読み、非空・HTTPS を確認して返す。
 *
 * `ownProperty` で読むのは、`parseJsonWithoutPrototype` のプロトタイプ除去と重ねる多層防御
 * （`own-property.ts`）。鎖読みへ戻すと、当該メンバを持たない Metadata でも
 * `Object.prototype` の汚染値が「AS が宣言したエンドポイント」に化ける（fail-open）。
 */
function requireHttpsEndpoint(parsed: object, key: string): string {
  const value = ownProperty<unknown>(parsed, key);
  if (!isNonBlankString(value)) {
    throw asMetadataFailure('missing_endpoint');
  }
  if (!isPublicHttpsUrl(value)) {
    throw asMetadataFailure('non_https_endpoint');
  }
  return value;
}

/**
 * AS Metadata 文書を取得し、`issuer` が取得に用いた AS 識別子と一致することを確認する
 * （RFC 8414 §3.3: 応答の `issuer` は取得に使った識別子と同一でなければならない）。
 *
 * 同一 origin の別テナント / 別 realm の文書を返す AS で照合を省くと、別テナントの
 * `token_endpoint` を信じて `pre-authorized_code` / `tx_code` / `client_assertion` をそこへ
 * 送る（Metadata すり替え / mix-up）。`issuer` の欠落・非文字列・不一致はいずれも
 * `issuer_mismatch` で fail-closed にする。
 */
async function fetchVerifiedAuthorizationServerDocument(
  authorizationServer: string,
  fetchImpl: FetchLike | undefined,
): Promise<object> {
  const parsed = await fetchInsertedWellKnownJson(
    authorizationServer,
    AS_METADATA_PATH,
    fetchImpl,
    asMetadataFailure,
  );
  const issuer = ownProperty<unknown>(parsed, 'issuer');
  if (typeof issuer !== 'string' || !sameIdentifier(issuer, authorizationServer)) {
    throw asMetadataFailure('issuer_mismatch');
  }
  return parsed;
}

/**
 * AS Metadata を取得し、PAR / Authorization / Token エンドポイントを解決する。
 *
 * 手順:
 * 1. `authorizationServer` が HTTPS でなければ**取得せずに**拒否する（fetch は一切発生しない）。
 * 2. `GET {origin}/.well-known/oauth-authorization-server{path}`（RFC 8414 §3.1 の挿入形。
 *    path 無しの識別子は `{authorizationServer}/.well-known/oauth-authorization-server`）を
 *    10 秒のタイムアウト付きで行う（本文読了までを覆う）。
 * 3. リダイレクト後の最終 URL が HTTPS を外れていれば拒否する（平文降格の防止）。
 * 4. 非 2xx / JSON 不正を拒否する。
 * 5. `pushed_authorization_request_endpoint` / `authorization_endpoint` / `token_endpoint` の
 *    3 つを own 限定で読み、いずれかの欠落・非 HTTPS を拒否する。
 *
 * 1〜4 は `internal/auth/well-known-json/index.ts` が Issuer Metadata 取得と共有する。
 *
 * @param authorizationServer AS の識別子（Issuer Metadata の `authorization_servers` の要素、
 *                            または告知が無い場合の `credential_issuer`。HTTPS の絶対 URL）。
 * @param fetchImpl HTTP 呼び出しの差し替えシーム（テスト注入用）。省略時はグローバル `fetch`。
 * @returns 検証済みの PAR / Authorization / Token エンドポイント。
 * @throws 非 HTTPS / 通信失敗 / タイムアウト / 非 2xx / リダイレクト降格 / 非 JSON Content-Type /
 *         本文の 1 MiB 超過 / JSON 不正 / エンドポイント欠落 / 非 HTTPS エンドポイントの場合
 *         （VericertsError、code `3004`）。Content-Type とサイズ上限は共有トランスポート由来で、
 *         **Content-Type を付けない / JSON 系でない AS は fail-closed になる**。
 *
 * @experimental 挙動・シグネチャが変わることがある（v1.0 で `@stable` 昇格予定）。
 */
export async function fetchAuthorizationServerMetadata(
  authorizationServer: string,
  fetchImpl?: FetchLike,
): Promise<AuthorizationServerEndpoints> {
  const parsed = await fetchVerifiedAuthorizationServerDocument(authorizationServer, fetchImpl);
  // このフローでは PAR が必須のため、告知が無ければ fail-closed（PAR を省く経路は作らない）。
  return {
    // `fetchVerifiedAuthorizationServerDocument` が `issuer` を文字列として検証済み。
    issuer: ownProperty<string>(parsed, 'issuer') as string,
    parEndpoint: requireHttpsEndpoint(parsed, 'pushed_authorization_request_endpoint'),
    authorizationEndpoint: requireHttpsEndpoint(parsed, 'authorization_endpoint'),
    tokenEndpoint: requireHttpsEndpoint(parsed, 'token_endpoint'),
  };
}

/**
 * AS Metadata から `token_endpoint` だけを解決する（pre-authorized_code 経路用。OID4VCI 1.0 §6）。
 *
 * Token Endpoint は Authorization Server が持つ（Issuer Metadata に `token_endpoint` は無い）。
 * pre-authorized_code 経路は PAR / Authorization Endpoint を使わないため、それらを必須にする
 * {@link fetchAuthorizationServerMetadata} ではなく本関数を使う（PAR を持たない AS でも受領できる）。
 * 取得・入口検査・`issuer` 照合・失敗理由は {@link fetchAuthorizationServerMetadata} と同一。
 *
 * @param authorizationServer AS の識別子（HTTPS の絶対 URL。path 成分を持ってよい）。
 * @param fetchImpl HTTP 呼び出しの差し替えシーム（テスト注入用）。省略時はグローバル `fetch`。
 * @returns 検証済み（HTTPS・公開ホスト）の Token Endpoint。
 * @throws 取得失敗 / `issuer` 不一致 / `token_endpoint` の欠落・非 HTTPS の場合（VericertsError、code `3004`）。
 */
export async function fetchAuthorizationServerTokenEndpoint(
  authorizationServer: string,
  fetchImpl?: FetchLike,
): Promise<string> {
  const parsed = await fetchVerifiedAuthorizationServerDocument(authorizationServer, fetchImpl);
  return requireHttpsEndpoint(parsed, 'token_endpoint');
}
