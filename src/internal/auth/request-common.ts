/**
 * OID4VP `PresentationRequest` の共通型と構築ロジック。
 *
 * クエリパラメータ形式（`request.ts` の `parseAuthorizationRequest`）と JAR 形式
 * （`jar/parse-jar.ts` の `parseJarRequest`）の両方から使う「入力形式に依らない」部分を集約する
 * （1 ファイル 300 行の Linterly 上限のため分離）。入力形式ごとのクレーム取り出しは
 * 各呼び出し元が own 限定で行い、本モジュールへは正規化済みの値だけを渡す。
 */

import { isLoA, type LoA } from '../credential/evidence-tou/evidence.js';
import { ErrorCodes, VericertsError } from '../errors.js';
import { isPublicHttpsUrl } from '../http/public-https-url.js';
import { comparableOrigin } from '../https-url.js';
import { ownProperty } from '../prototype-safety/own-property.js';
import type { DcqlQuery } from './dcql/dcql.js';
import type { EncodedTransactionData } from './request-v2.js';

/** `response_uri` に要求するスキーム。 */
const HTTPS_PROTOCOL = 'https:';

/**
 * パース済み OID4VP Authorization Request。
 *
 * `dcql_query`（DCQL）と `presentation_definition`（PEx v2）の両形式を扱う。
 * PEx v2 定義は候補の照合時に評価するため、ここでは生 JSON として保持する。
 */
export interface PresentationRequest {
  /** `vp_token`（OID4VP では固定）。 */
  readonly responseType: string;
  /** 検証者の識別子（URL）。 */
  readonly clientId: string;
  /** レスポンスモード（`direct_post` / `direct_post.jwt`）。 */
  readonly responseMode: string;
  /** VP Token の送信先 URL。 */
  readonly responseUri: string;
  /** リプレイ防止ナンス。 */
  readonly nonce: string;
  /** リクエスト識別子。 */
  readonly state: string;
  /** DCQL クエリ（`dcql_query` 指定時）。 */
  readonly dcqlQuery?: DcqlQuery;
  /** PEx v2 Presentation Definition の生 JSON（`presentation_definition` 指定時）。 */
  readonly presentationDefinition?: Readonly<Record<string, unknown>>;
  /**
   * Verifier の `client_metadata`（生 JSON）。`response_mode=direct_post.jwt` の応答暗号化で
   * `authorization_encrypted_response_alg` / `_enc` と `jwks` の `use:"enc"` 鍵を参照する。
   */
  readonly clientMetadata?: Readonly<Record<string, unknown>>;
  /**
   * OID4VP `transaction_data`（EUDI / HAIP）の生 base64url 文字列配列。`extractTransactionData`
   * への入力であり、ハッシュ整合のためデコードせず受領した文字列のまま保持する。
   */
  readonly transactionData?: readonly EncodedTransactionData[];
  /**
   * Verifier が要求する最低 LoA（Level of Assurance、`required_loa`）。OID4VP 標準にはない
   * Vericerts 拡張パラメータ（`transaction_data` 等と同様のカスタムクレーム／クエリパラメータ）。
   * `createPresentation` の LoA 判定フック（`opts.checkLoa`）が選択 VC の
   * `evidence`（`verifyEvidence`）と突き合わせる際の要求値として使う。
   *
   * パラメータ自体が未指定（`undefined`）なら LoA 判定は不要という意味であり許容するが、
   * 告知はされたのに `low` / `substantial` / `high` のいずれでもない値（大文字表記・前後空白等）は
   * `buildRequest` が `OID4VP_REQUEST_PARSE_FAILED`（8030）で拒否する。「未指定」へ丸めてしまうと
   * Verifier が LoA を要求しているのに判定自体が無言でスキップされる（実質 fail-open）ため。
   */
  readonly requiredLoA?: LoA;
}

/**
 * `response_uri` が VP Token の送信先として安全であることを検証する。
 *
 * 1. `response_uri` が有効な絶対 URL であること
 * 2. スキームが `https` であること。`client_id` と `response_uri`
 *    が同一オリジンでも、両方 `http://` なら VP Token が平文で送られてしまうため、origin 一致検査
 *    だけでは不十分。開発向けの loopback 例外は設けない（`did:web` の `method-web.ts` や JSON
 *    Schema 取得の `json-schema/fetch-document.ts` と同じく、SDK は常に https を要求する）
 * 3. ホストが公開宛であること（`isPublicHttpsUrl`。ループバック / プライベート / リンクローカルを拒否）
 * 4. `client_id` が origin を取れる URL であること（`comparableOrigin`）。署名なしの直接形式
 *    （および署名未検証の `parseJarRequest`）では `client_id` を攻撃者が自由に決められ、スキームなし・
 *    `x509_san_dns:` 等の prefixed・DID・userinfo 付き URL は `response_uri` と突き合わせる origin を
 *    持たない。これらを受理すると同意 UI の表示 RP と VP Token の送信先が食い違うため
 *    `client_id_not_url` で拒否する（SIOPv2 の）
 * 5. `client_id` の origin が `response_uri` の origin と一致すること（フィッシング防止）
 */
function assertResponseUriIsSafe(clientId: string, responseUri: string): void {
  let url: URL;
  try {
    url = new URL(responseUri);
  } catch {
    throw new VericertsError(ErrorCodes.OID4VP_REQUEST_PARSE_FAILED);
  }
  if (url.protocol !== HTTPS_PROTOCOL) {
    throw new VericertsError(ErrorCodes.OID4VP_REQUEST_PARSE_FAILED, {
      context: { reason: 'insecure_response_uri' },
    });
  }
  // 公開ホスト宛であること（ループバック / プライベート / リンクローカル宛への VP Token 送信は
  // SSRF の入口になる）。提出時（`oid4vp-submit.ts`）も同じ検査を重ねる。
  if (!isPublicHttpsUrl(responseUri)) {
    throw new VericertsError(ErrorCodes.OID4VP_REQUEST_PARSE_FAILED, {
      context: { reason: 'non_public_response_uri' },
    });
  }
  const clientOrigin = comparableOrigin(clientId);
  if (clientOrigin === undefined) {
    throw new VericertsError(ErrorCodes.OID4VP_REQUEST_PARSE_FAILED, {
      context: { reason: 'client_id_not_url' },
    });
  }
  if (clientOrigin !== url.origin) {
    throw new VericertsError(ErrorCodes.OID4VP_REQUEST_PARSE_FAILED, {
      context: { reason: 'response_uri_client_id_mismatch' },
    });
  }
}

/**
 * 128 ビットの値を base64url 表現した場合を基準とする `nonce` の最小文字数。
 *
 * エントロピーは文字列からは測れないため、128 bit（16 バイト）を base64url で表した最短の長さ
 * （22 文字）を下限にする。hex（32 文字）・UUID（36 文字）など他の一般的な表記はこれを満たす。
 */
export const MIN_NONCE_LENGTH = 22;

/** 共通の必須クレーム検証と Request 構造組み立て。 */
export function buildRequest(params: {
  responseType: unknown;
  clientId: unknown;
  responseMode: unknown;
  responseUri: unknown;
  nonce: unknown;
  state: unknown;
  dcqlQuery?: DcqlQuery;
  presentationDefinition?: Record<string, unknown>;
  clientMetadata?: Record<string, unknown>;
  transactionData?: readonly EncodedTransactionData[];
  requiredLoA?: unknown;
}): PresentationRequest {
  const { responseType, clientId, responseMode, responseUri, nonce, state } = params;
  for (const value of [responseType, clientId, responseMode, responseUri, nonce, state]) {
    if (typeof value !== 'string' || value.length === 0) {
      throw new VericertsError(ErrorCodes.OID4VP_REQUEST_PARSE_FAILED);
    }
  }
  if (responseType !== 'vp_token') {
    throw new VericertsError(ErrorCodes.OID4VP_REQUEST_PARSE_FAILED, {
      context: { reason: 'unsupported_response_type' },
    });
  }
  // 上の非空検査で string と確定している。短い nonce はリプレイ耐性（Verifier 側の乱数性）の前提を欠く。
  if ((nonce as string).length < MIN_NONCE_LENGTH) {
    throw new VericertsError(ErrorCodes.OID4VP_REQUEST_PARSE_FAILED, {
      context: { reason: 'nonce_too_short' },
    });
  }
  assertResponseUriIsSafe(clientId as string, responseUri as string);

  // 任意メンバは自身のプロパティに限って読む。**現行の呼び出し元（`parseRequestUri` / `parseJarRequest`）は 4 キーすべてを
  // 持つリテラルを渡すため本ヘルパーは到達しない**（直接読みに戻しても挙動は変わらない）。呼び出し側由来の `params` を
  // 組み立てる将来の呼び出し元で、継承値が自身のプロパティへ昇格し下流の `Object.hasOwn` 判定を無力化するのを防ぐ。
  const opt = <T>(key: string): T | undefined => ownProperty<T>(params, key);
  const dcqlQuery = opt<DcqlQuery>('dcqlQuery');
  const presentationDefinition = opt<Record<string, unknown>>('presentationDefinition');
  const clientMetadata = opt<Record<string, unknown>>('clientMetadata');
  const transactionData = opt<readonly EncodedTransactionData[]>('transactionData');
  // `requiredLoA` は Verifier 由来の生値（クエリパラメータ文字列 / JAR クレーム）であり、
  // `low` / `substantial` / `high` のいずれでもない値は検証せずキャストしない（own-property.ts の
  // 注意）。「未指定」（`undefined`）は LoA 判定自体が不要という正当な状態のため許容するが、
  // **告知はされたが値が不正**（大文字表記・前後空白・別表記ゆれ等）は「未指定」に丸めてしまうと
  // `opts.checkLoa` の LoA 判定が無言でスキップされ、実質 fail-open になる。
  // 告知された以上は認識できる値でなければ拒否し、Request パース自体を fail-closed に倒す。
  const requiredLoARaw = opt<unknown>('requiredLoA');
  if (requiredLoARaw !== undefined && !isLoA(requiredLoARaw)) {
    throw new VericertsError(ErrorCodes.OID4VP_REQUEST_PARSE_FAILED, {
      context: { reason: 'invalid_required_loa' },
    });
  }
  const requiredLoA = requiredLoARaw as LoA | undefined;
  const request: PresentationRequest = {
    responseType: responseType as string,
    clientId: clientId as string,
    responseMode: responseMode as string,
    responseUri: responseUri as string,
    nonce: nonce as string,
    state: state as string,
    ...(dcqlQuery !== undefined ? { dcqlQuery } : {}),
    ...(presentationDefinition !== undefined ? { presentationDefinition } : {}),
    ...(clientMetadata !== undefined ? { clientMetadata } : {}),
    ...(transactionData !== undefined ? { transactionData } : {}),
    ...(requiredLoA !== undefined ? { requiredLoA } : {}),
  };
  return request;
}
