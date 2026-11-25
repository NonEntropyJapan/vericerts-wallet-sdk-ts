/**
 * DIDベース SIOPv2 Authorization Request のパース。
 *
 * 次の 2 通りの入力を受け付け、同じ `SIOPv2Request` へ展開する。
 * - `siopv2://?scope=openid&response_type=id_token&client_id=...&redirect_uri=...&nonce=...
 *   &registration=<url-encoded-json>` 形式のクエリ（URI）。
 * - 同じパラメータを持つ JSON オブジェクト（vericerts-anchor が返す `authorization_request` をそのまま渡せる。
 *   `siopv2://` URI へは変換しない）。`client_metadata` / `registration` はオブジェクトでも JSON 文字列でもよい。
 *
 * 独自の `extractQuery` を持つ（`auth/oid4vp/oid4vp-request-query.ts` の同名関数は再利用しない）: あちらは
 * 空クエリを OID4VP 固有のコード（`8030 OID4VP_REQUEST_PARSE_FAILED`）で拒否する設計であり、
 * SIOPv2 の空クエリは `4001 SIOPV2_REQUEST_PARSE_FAILED` で拒否しなければならない。共有すると
 * 一方の変更がもう一方のコードを黙って変えてしまう。
 *
 * セキュリティ上の注意: 例外メッセージ・`context` に requestURI・
 * registration の内容を含めない。
 */

import { ErrorCodes, VericertsError } from '../../errors.js';
import { isPublicHttpsUrl } from '../../http/public-https-url.js';
import { comparableOrigin } from '../../https-url.js';
import { isNonBlankString } from '../../prototype-safety/non-empty-string.js';
import { ownProperty } from '../../prototype-safety/own-property.js';
import { parseMetadata } from './rp-metadata.js';
import type { RPRegistration, SIOPv2Request } from './types.js';
import { requestsVpToken } from './vp-token.js';

/** SIOPv2 Authorization Request が必須とするスコープ。 */
const REQUIRED_SCOPE = 'openid';
/** ID Token を要求するレスポンスタイプの必須トークン（`id_token` / `vp_token id_token`）。 */
const REQUIRED_RESPONSE_TYPE_TOKEN = 'id_token';
/** `redirect_uri` に要求するスキーム（RP へ ID Token を平文送信しないため）。 */
const HTTPS_PROTOCOL = 'https:';

/** 要求のパラメータ名 → 値の読み出し（URI のクエリ / JSON オブジェクトの差を隠す）。 */
type ParamReader = (name: string) => unknown;

/** Authorization Request URI からクエリ文字列を抽出する。空クエリは `4001` で拒否する。 */
function extractSiopQuery(requestUri: string): URLSearchParams {
  const queryStart = requestUri.indexOf('?');
  const raw = queryStart >= 0 ? requestUri.slice(queryStart + 1) : requestUri;
  if (raw.length === 0) {
    throw new VericertsError(ErrorCodes.SIOPV2_REQUEST_PARSE_FAILED, {
      context: { reason: 'empty_query' },
    });
  }
  return new URLSearchParams(raw);
}

/** 入力（URI 文字列 / JSON オブジェクト）からパラメータの読み出し関数を作る。 */
function paramReader(input: string | Readonly<Record<string, unknown>>): ParamReader {
  if (typeof input === 'string') {
    const query = extractSiopQuery(input);
    return (name) => query.get(name) ?? undefined;
  }
  if (typeof input !== 'object' || input === null || Array.isArray(input)) {
    throw new VericertsError(ErrorCodes.SIOPV2_REQUEST_PARSE_FAILED, {
      context: { reason: 'request_shape' },
    });
  }
  // 要求の各値は own プロパティに限って読む（省略したパラメータが汚染値を採用しないため）。
  return (name) => ownProperty<unknown>(input, name);
}

/** VC を求める問い合わせのパラメータ（Wallet は評価しない。`vp_token` を要求する要求に載っていれば拒否する）。 */
const CREDENTIAL_QUERY_PARAMS = [
  'dcql_query',
  'presentation_definition',
  'presentation_definition_uri',
  'claims',
] as const;

/** パラメータが載っているか（URI 形式の空・空白のみの値、JSON 形式の `null` は載っていないものとして扱う）。 */
function hasParam(read: ParamReader, name: string): boolean {
  const value = read(name);
  if (typeof value === 'string') return isNonBlankString(value);
  return value !== undefined && value !== null;
}

/**
 * `client_metadata_uri`（RP メタデータの取得先。OID4VP §5.1 / SIOPv2 §7.2）を読む。省略・空白のみは `undefined`。
 *
 * 取得先は攻撃者が選べる QR / Deep Link 由来なので、公開 HTTPS URL に限る（取得自体は承認後の
 * `processSIOPv2Request` が行う。ここでは通信しない）。`client_metadata` と同時には使えない
 * （RP メタデータの出所が 2 つあると、どちらを信じるか曖昧になる）。
 *
 * @throws 公開 HTTPS URL でない・`client_metadata` と併記された場合（VericertsError、code `4001`）。
 */
function optionalClientMetadataUri(read: ParamReader): string | undefined {
  const uri = optionalStringParam(read, 'client_metadata_uri');
  if (uri === undefined) return undefined;
  if (!isPublicHttpsUrl(uri)) {
    throw new VericertsError(ErrorCodes.SIOPV2_REQUEST_PARSE_FAILED, {
      context: { reason: 'client_metadata_uri_not_public' },
    });
  }
  if (hasParam(read, 'client_metadata')) {
    throw new VericertsError(ErrorCodes.SIOPV2_REQUEST_PARSE_FAILED, {
      context: { reason: 'client_metadata_uri_conflict' },
    });
  }
  return uri;
}

/**
 * 任意の文字列パラメータを読む。省略・空白のみ・文字列でない値は `undefined`（旧来の `siopv2://` URI に空の
 * `state=` 等が付いていても拒否しない）。`vp_token` を要求する要求での必須検査は `assertVpTokenRequestSupported`。
 */
function optionalStringParam(read: ParamReader, name: string): string | undefined {
  const value = read(name);
  return isNonBlankString(value) ? value : undefined;
}

/**
 * RP メタデータのパラメータを読む（省略は `undefined`。空文字列も省略扱い。旧実装の `registration` と同じ）。
 *
 * `registration` は従来どおり、形が不正なら `4001`。`client_metadata` は標準の置き場所だが、他の形式の要求
 * （`vp_formats_supported` だけを載せる等）にも付き得るので、`vp_token` を要求しない要求では形が不正でも拒否せず
 * 無かったことにする（RP メタデータを使う `processSIOPv2Request` では `registration` へ倒れ、無ければ `4002`）。
 * `vp_token` を要求する要求では、検証できないメタデータで署名してしまわないよう `4001` で拒否する。
 */
function optionalMetadataParam(
  read: ParamReader,
  name: 'registration' | 'client_metadata',
  strict: boolean,
): RPRegistration | undefined {
  const raw = read(name);
  if (raw === undefined || (typeof raw === 'string' && !isNonBlankString(raw))) return undefined;
  if (strict || name === 'registration') return parseMetadata(raw, name, strict);
  try {
    return parseMetadata(raw, name, strict);
  } catch {
    return undefined;
  }
}

/**
 * DID ベースの SIOPv2 Authorization Request（`siopv2://` URI または JSON オブジェクト）をパースする。
 *
 * @param input `siopv2://?scope=openid&response_type=id_token&...` 形式の URI、または同じパラメータを持つ JSON オブジェクト。
 * @returns 正規化された `SIOPv2Request`。
 * @throws 必須パラメータ欠落・`redirect_uri` が非 HTTPS・`registration` の JSON 構文不正・`vp_token` を要求する要求の
 *   `client_metadata` の形不正の場合（VericertsError、code `4001`）。`state` 等の `vp_token` 固有の検査は
 *   `processSIOPv2Request`（`assertVpTokenRequestSupported`）が行う。
 */
export function parseSIOPv2Request(
  input: string | Readonly<Record<string, unknown>>,
): SIOPv2Request {
  const read = paramReader(input);

  const scope = read('scope');
  const responseType = read('response_type');
  const clientId = read('client_id');
  const redirectUri = read('redirect_uri');
  const nonce = read('nonce');

  if (
    !isNonBlankString(scope) ||
    !scope.split(' ').includes(REQUIRED_SCOPE) ||
    !isNonBlankString(responseType) ||
    !responseType.split(' ').includes(REQUIRED_RESPONSE_TYPE_TOKEN) ||
    !isNonBlankString(clientId) ||
    !isNonBlankString(redirectUri) ||
    !isNonBlankString(nonce)
  ) {
    throw new VericertsError(ErrorCodes.SIOPV2_REQUEST_PARSE_FAILED, {
      context: { reason: 'missing_required_param' },
    });
  }

  let redirectUrl: URL;
  try {
    redirectUrl = new URL(redirectUri);
  } catch {
    throw new VericertsError(ErrorCodes.SIOPV2_REQUEST_PARSE_FAILED, {
      context: { reason: 'redirect_uri_malformed' },
    });
  }
  if (redirectUrl.protocol !== HTTPS_PROTOCOL) {
    throw new VericertsError(ErrorCodes.SIOPV2_REQUEST_PARSE_FAILED, {
      context: { reason: 'redirect_uri_scheme' },
    });
  }
  // `redirect_uri` は攻撃者が選べる QR / Deep Link 由来で、ID Token が POST される。OID4VP の
  // `response_uri`（`assertResponseUriIsSafe`）と同じく公開ホスト宛に限る。
  if (!isPublicHttpsUrl(redirectUri)) {
    throw new VericertsError(ErrorCodes.SIOPV2_REQUEST_PARSE_FAILED, {
      context: { reason: 'redirect_uri_not_public' },
    });
  }
  // `client_id` は署名なしのクエリで来るため、`redirect_uri` と同一 origin の https URL に限って受理する
  // （OID4VP 経路の `response_uri` ↔ `client_id` 束縛と同一ロジック）。これが無いと攻撃者が任意 RP 宛
  // （aud = client_id）の ID Token を自分の `redirect_uri` へ取得できる。DID 形式の `client_id` は
  // 署名付き Request Object（JAR）無しでは origin を検証できないため、この経路では拒否する。
  const clientOrigin = comparableOrigin(clientId);
  if (clientOrigin === undefined || clientOrigin !== comparableOrigin(redirectUri)) {
    throw new VericertsError(ErrorCodes.SIOPV2_REQUEST_PARSE_FAILED, {
      context: { reason: 'client_id_redirect_uri_origin_mismatch' },
    });
  }

  const state = optionalStringParam(read, 'state');
  const responseMode = optionalStringParam(read, 'response_mode');
  const idTokenType = optionalStringParam(read, 'id_token_type');
  const wantsVpToken = requestsVpToken(responseType);
  const clientMetadataUri = optionalClientMetadataUri(read);
  const clientMetadata = optionalMetadataParam(read, 'client_metadata', wantsVpToken);
  const registration = optionalMetadataParam(read, 'registration', wantsVpToken);

  const requestsCredentials = CREDENTIAL_QUERY_PARAMS.some((name) => hasParam(read, name));

  return {
    scope,
    responseType,
    clientId,
    redirectUri,
    nonce,
    state,
    responseMode,
    idTokenType,
    ...(requestsCredentials ? { requestsCredentials } : {}),
    clientMetadata,
    registration,
    ...(clientMetadataUri !== undefined ? { clientMetadataUri } : {}),
  };
}
