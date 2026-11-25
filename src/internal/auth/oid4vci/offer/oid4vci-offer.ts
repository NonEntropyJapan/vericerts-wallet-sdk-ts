/**
 * OID4VCI Credential Offer 解析。
 *
 * Wallet が受領した Credential Offer URI を解析し、`CredentialOffer` 構造に正規化する。
 * Offer URI は次の 2 形式を取りうる（OpenID for Verifiable Credential Issuance, Draft 17+）:
 *   - 値渡し: `openid-credential-offer://?credential_offer=<url-encoded-json>`
 *   - 参照渡し: `openid-credential-offer://?credential_offer_uri=https://issuer.example.com/offers/123`
 *
 * 参照渡しの場合は `credential_offer_uri` を HTTPS GET で取得して JSON を得る
 * （by-reference fetch）。本モジュールは Offer の「解析」のみを担い、
 * Issuer Metadata 取得・Token Request・Credential Request は
 * 別スコープ（後続 Issue）で実装する。
 *
 * エラーコード粒度（3003 / 3004）:
 * - URI 形式不正 / JSON parse 失敗 / Offer 構造不正 → `OFFER_URI_PARSE_FAILED`（3003、再試行不可）。
 * - `credential_offer_uri` の取得失敗（ネットワーク / タイムアウト / HTTP 4xx・5xx /
 *   非 HTTPS） → `ISSUER_COMMUNICATION_FAILED`（3004、再試行可）。
 *
 * セキュリティ上の注意:
 * - 例外メッセージや `context` に URI・レスポンス本文・PII を含めない。
 * - `credential_offer_uri` は HTTPS のみ許可し、リダイレクト後も HTTPS にとどまることを検証する
 *   （平文取得による Offer すり替えを防ぐ）。
 */

import { ErrorCodes, VericertsError } from '../../../errors.js';
import { type FetchLike, resolveInjectedFetch } from '../../../fetch-di.js';
import {
  declaresOversizedBody,
  discardBody,
  isAllowedContentType,
  readBodyWithinLimit,
} from '../../../http/body-limit.js';
import { isPublicHttpsUrl } from '../../../http/public-https-url.js';
import {
  bindForPublicRedirects,
  fetchFollowingPublicRedirects,
} from '../../../http/public-redirect-fetch.js';
import { isBoundedStringList } from '../../../primitives/bounded-input.js';
import { CREDENTIAL_CONFIGURATION_ID_LIMITS } from '../../../primitives/oid4vci-input-limits.js';
import { ownProperty } from '../../../prototype-safety/own-property.js';
import { parseJsonWithoutPrototype } from '../../../prototype-safety/parse-json.js';
import { type CredentialGrants, parseGrants } from './oid4vci-offer-grants.js';

// grant の型・キー定数は `oid4vci-offer-grants.ts` に移したが、Offer の型として一体で読まれる
// ため本モジュールから引き続き再エクスポートする（利用者の import 元を変えない）。
export {
  AUTHORIZATION_CODE_GRANT,
  type AuthorizationCodeGrant,
  type CredentialGrants,
  PRE_AUTHORIZED_CODE_GRANT,
  type PreAuthorizedCodeGrant,
} from './oid4vci-offer-grants.js';
export type { TxCode } from './tx-code.js';

/** Offer URI のカスタムスキーム。 */
const OFFER_URI_SCHEME = 'openid-credential-offer:';

/** `credential_offer_uri` 取得のタイムアウト（ミリ秒）。did:web 解決と揃える。 */
const FETCH_TIMEOUT_MS = 10_000;

/** 取得レスポンスで受理する Content-Type（パラメータ部 `; charset=...` は除いて判定）。 */
const ALLOWED_CONTENT_TYPES: ReadonlyArray<string> = ['application/json'];

/**
 * Credential Offer 構造。
 *
 * `credential_configuration_ids` は Issuer Metadata の
 * `credential_configurations_supported` のキーを参照し、発行対象の VC 構成を解決する。
 */
export interface CredentialOffer {
  /** 発行者の識別子（Issuer Metadata 取得のベース URL）。 */
  readonly credential_issuer: string;
  /** 発行対象の credential configuration ID 群（Metadata のキーを参照、空配列不可）。 */
  readonly credential_configuration_ids: string[];
  /** 認可フローの grant 群。省略可能（Authorization Code Flow 等）。 */
  readonly grants?: CredentialGrants;
}

/**
 * Offer URI から `credential_offer` / `credential_offer_uri` クエリ値を取り出す。
 *
 * スキームは `openid-credential-offer:` のみ受理する。両方のパラメータが同時に存在する、
 * またはどちらも存在しない場合は形式不正として拒否する（OID4VCI: 値渡しと参照渡しは排他）。
 *
 * @param offerURI Offer URI 文字列。
 * @returns 値渡し JSON 文字列、または参照 URL のいずれか。
 * @throws スキーム不正・パラメータ排他違反・URI 解析不能の場合（VericertsError、code `3003`）。
 */
function extractOfferParams(
  offerURI: string,
): { kind: 'inline'; json: string } | { kind: 'reference'; uri: string } {
  let url: URL;
  try {
    url = new URL(offerURI);
  } catch {
    // 入力が含まれ得るため cause を渡さず正規化する。
    throw new VericertsError(ErrorCodes.OFFER_URI_PARSE_FAILED);
  }
  if (url.protocol !== OFFER_URI_SCHEME) {
    throw new VericertsError(ErrorCodes.OFFER_URI_PARSE_FAILED);
  }
  // URL は `credential_offer` の `=`/`&` を含む JSON も searchParams で正しくデコードする。
  const inline = url.searchParams.get('credential_offer');
  const reference = url.searchParams.get('credential_offer_uri');
  if ((inline === null) === (reference === null)) {
    // 両方 null（どちらも無い） or 両方非 null（排他違反）。
    throw new VericertsError(ErrorCodes.OFFER_URI_PARSE_FAILED);
  }
  if (inline !== null) {
    return { kind: 'inline', json: inline };
  }
  // reference は上の排他チェックで非 null が保証される。
  return { kind: 'reference', uri: reference as string };
}

/**
 * `credential_offer_uri` を HTTPS GET で取得し、本文 JSON 文字列を返す（by-reference）。
 *
 * HTTPS のみ許可し、リダイレクト後の最終 URL も HTTPS であることを検証する。取得失敗
 * （非 HTTPS / ネットワーク / タイムアウト / HTTP 非 2xx / Content-Type 不一致）は
 * `ISSUER_COMMUNICATION_FAILED`（3004、再試行可）に正規化する。
 *
 * @param uri `credential_offer_uri` の値。
 * @param fetchImpl HTTP 呼び出しの差し替えシーム。省略時はグローバル `fetch`。受領フローの
 * 初弾もホストアプリが注入した `fetch`（証明書ピン留め / プロキシ済み）の内側に留めるため、
 * 後続の `fetchIssuerMetadata` と同じシームを通す（`wallet/options.ts` の `eudiFetchImpl` 契約）。
 * 本文は `MAX_DOCUMENT_BYTES`（1 MiB）の内側で読み、`clearTimeout` は本文読了後に行う
 * （`http/body-limit.ts`）。`credential_offer_uri` は QR / Deep Link 由来で攻撃者が選べるため、
 * 上限も abort 窓も本文読み出しまで及ばせる。
 *
 * @returns レスポンス本文（JSON 文字列）。
 * @throws 取得失敗（タイムアウト / 非 HTTPS リダイレクト / 上限超過を含む）の場合
 *   （VericertsError、code `3004`）。
 */
async function fetchOfferByReference(
  uri: string,
  fetchImpl: FetchLike | undefined,
): Promise<string> {
  let url: URL;
  try {
    url = new URL(uri);
  } catch {
    // 取り直しが必要な発行者由来の値のため通信失敗（3004）に分類する。
    throw new VericertsError(ErrorCodes.ISSUER_COMMUNICATION_FAILED);
  }
  // `credential_offer_uri` は QR / Deep Link 由来で攻撃者が選べる。取得前に公開 HTTPS 宛であることを
  // 確かめ、内部ホスト・クラウドメタデータ宛の blind SSRF を作らない。
  if (!isPublicHttpsUrl(url.toString())) {
    throw new VericertsError(ErrorCodes.ISSUER_COMMUNICATION_FAILED);
  }
  const controller = new AbortController();
  // 本文の読み出しまでを 1 つのタイムアウトで覆う（`clearTimeout` は本文読了後）。
  const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
  // 読まずに失敗へ倒す経路でも本文を解放できるよう、`finally` から見える位置で宣言する。
  let response: Response | undefined;
  try {
    try {
      // `fetchImpl` は関数値 DI なので `resolveInjectedFetch`（横断 `internal/fetch-di.ts`）で
      // 解決し、`doFetch.call(receiver, ...)` の形で呼ぶ（裸呼び出しは prototype メソッド実装の
      // `this` を壊す）。`fetchImpl` は常に own プロパティとして載せる（省略時も）。空リテラルを
      // 渡すと `Object.prototype.fetchImpl` の汚染値を掴み、取得ごと攻撃者へ委譲される。
      // GET の init に `body` は載せない（`http/get-fetch.ts`）。リダイレクトはホップごとに
      // 公開 HTTPS 宛へ縛って追従する（`http/public-redirect-fetch.ts`）。
      const { doFetch, receiver } = resolveInjectedFetch({ fetchImpl });
      response = await fetchFollowingPublicRedirects(
        bindForPublicRedirects(doFetch, receiver),
        url.toString(),
        {
          method: 'GET',
          signal: controller.signal,
          headers: { Accept: ALLOWED_CONTENT_TYPES.join(', ') },
        },
      );
    } catch {
      // ネットワークエラー / タイムアウト（abort）。詳細は秘密を含み得るため正規化する。
      throw new VericertsError(ErrorCodes.ISSUER_COMMUNICATION_FAILED);
    }
    // リダイレクト先が HTTPS にとどまっていることを最終 URL のスキームで検証する
    // （判定は共有ヘルパー `https-url.ts` に寄せる）。
    if (response.url.length > 0 && !isPublicHttpsUrl(response.url)) {
      throw new VericertsError(ErrorCodes.ISSUER_COMMUNICATION_FAILED);
    }
    if (!response.ok) {
      throw new VericertsError(ErrorCodes.ISSUER_COMMUNICATION_FAILED);
    }
    // 判定は共有ヘルパー（`http/body-limit.ts`）に寄せる。ヘッダ欠落は既定どおり拒否する。
    if (!isAllowedContentType(response.headers.get('content-type'), ALLOWED_CONTENT_TYPES)) {
      throw new VericertsError(ErrorCodes.ISSUER_COMMUNICATION_FAILED);
    }
    // 自己申告の `content-length` で早期に落とし、実バイト数でも打ち切る。
    if (declaresOversizedBody(response)) {
      throw new VericertsError(ErrorCodes.ISSUER_COMMUNICATION_FAILED);
    }
    let text: string | undefined;
    try {
      text = await readBodyWithinLimit(response);
    } catch {
      // 本文読み出し中のネットワークエラー / abort。本文・URL は載せない。
      throw new VericertsError(ErrorCodes.ISSUER_COMMUNICATION_FAILED);
    }
    if (text === undefined) {
      throw new VericertsError(ErrorCodes.ISSUER_COMMUNICATION_FAILED);
    }
    return text;
  } finally {
    clearTimeout(timer);
    // 本文を読まずに throw した経路が接続を掴んだまま残らないようにする（読了後は no-op）。
    discardBody(response);
  }
}

/**
 * JSON 文字列を `CredentialOffer` に検証・正規化する。
 *
 * 必須フィールド:
 * - `credential_issuer`: 非空文字列。
 * - `credential_configuration_ids`: 非空の文字列配列（各要素も非空）。件数・長さの合計は
 *   `CREDENTIAL_CONFIGURATION_ID_LIMITS` 以内（超過は拒否）。
 *
 * @param text Offer の JSON 文字列。
 * @returns 検証済み `CredentialOffer`。
 * @throws JSON parse 失敗・構造不正の場合（VericertsError、code `3003`）。
 */
function parseOfferJson(text: string): CredentialOffer {
  let parsed: unknown;
  try {
    parsed = parseJsonWithoutPrototype(text);
  } catch {
    // 本文に入力が含まれ得るため cause を渡さず正規化する。
    throw new VericertsError(ErrorCodes.OFFER_URI_PARSE_FAILED);
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    throw new VericertsError(ErrorCodes.OFFER_URI_PARSE_FAILED);
  }
  const obj = parsed as Record<string, unknown>;
  const credentialIssuer = ownProperty<unknown>(obj, 'credential_issuer');
  if (typeof credentialIssuer !== 'string' || credentialIssuer.length === 0) {
    throw new VericertsError(ErrorCodes.OFFER_URI_PARSE_FAILED);
  }
  const ids = ownProperty<unknown>(obj, 'credential_configuration_ids');
  // 件数・1 件長・合計長の上限。件数は走査の前に判定する。
  if (
    !Array.isArray(ids) ||
    ids.length === 0 ||
    !isBoundedStringList(ids, CREDENTIAL_CONFIGURATION_ID_LIMITS, (id) => id.length > 0)
  ) {
    throw new VericertsError(ErrorCodes.OFFER_URI_PARSE_FAILED);
  }
  const grants = parseGrants(ownProperty<unknown>(obj, 'grants'));
  const offer: CredentialOffer = {
    credential_issuer: credentialIssuer,
    credential_configuration_ids: [...ids],
    ...(grants !== undefined ? { grants } : {}),
  };
  return offer;
}

/**
 * Credential Offer URI を解析して `CredentialOffer` を返す。
 *
 * 手順:
 * 1. URI から `credential_offer`（値渡し JSON）または `credential_offer_uri`（参照）を取り出す。
 * 2. 参照の場合は HTTPS GET で取得して JSON 文字列を得る（by-reference fetch）。
 * 3. JSON を検証して `CredentialOffer` に正規化する。
 *
 * @param offerURI `openid-credential-offer://` 形式の Offer URI。
 * @param fetchImpl 参照渡しの取得に使う `fetch` の差し替えシーム。省略時はグローバル `fetch`。
 *   `credential_offer_uri` は QR / Deep Link 由来で**攻撃者が選べる** URL なので、受領フローの
 *   初弾もホストアプリが注入した `fetch` の制御下に留める（`fetchIssuerMetadata` 以降と同じ
 *   シーム。`wallet/options.ts` の `eudiFetchImpl` 契約）。
 * @returns 検証済み `CredentialOffer`。
 * @throws URI / JSON / 構造不正（code `3003`）・参照取得失敗（code `3004`）の場合（VericertsError）。
 */
export async function parseCredentialOffer(
  offerURI: string,
  fetchImpl?: FetchLike,
): Promise<CredentialOffer> {
  const params = extractOfferParams(offerURI);
  const json =
    params.kind === 'inline' ? params.json : await fetchOfferByReference(params.uri, fetchImpl);
  return parseOfferJson(json);
}
