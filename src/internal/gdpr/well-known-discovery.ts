/**
 * DSR / DPO の `.well-known` 発見機構。
 *
 * SDK は DSR (Data Subject Request) 対応 SLA や DPO 任命自体は行わず、Issuer / RP ドメインが
 * 公開する機械可読な発見メタデータを取得・パースする機構のみを提供する:
 *   - `/.well-known/dsr-endpoint`: データ主体の権利
 *     (Art.15–22) 行使のための DSR 受付エンドポイントの参照。
 *   - `/.well-known/dpo-contact`: Data Protection Officer
 *     (Art.37–39) の連絡先メタデータの参照。
 *
 * 取得要件（他の `.well-known` 発見機構と同じ方針）は横断プリミティブ `http/fetch-json.ts` が
 * 担う: HTTPS GET・最終 URL の HTTPS 検査・タイムアウト 10 秒（本文読了まで 1 つの AbortController
 * で覆う）・Content-Type が JSON 系であること・本文 1 MiB 上限・プロトタイプを外したパース。
 * 本モジュールはドメイン → URL 変換と、取得した JSON の最小スキーマ検証だけを持つ
 * （メタデータ内の URL は HTTPS のみ受理する）。
 *
 * エラーコード粒度（10605、10606）:
 * - 取得失敗（ネットワークエラー / タイムアウト / HTTP 4xx・5xx / 非 HTTPS リダイレクト /
 *   本文の上限超過）→ `GDPR_DISCOVERY_FETCH_FAILED`（10605、再試行可）。
 * - Content-Type 不一致 / JSON parse 失敗 / スキーマ不正 → `GDPR_DISCOVERY_INVALID`（10606）。
 *
 * セキュリティ上の注意:
 * - 例外メッセージや `cause` にドメイン・URL・レスポンス本文を含めない（秘密が混入し得るため正規化）。
 * - TLS 1.2+ はランタイム（Bun/Node のグローバル `fetch`）の既定に依拠する。
 */

import { ErrorCodes, VericertsError } from '../errors.js';
import { fetchJsonWithinLimits, type JsonFetchReason } from '../http/fetch-json.js';
import { isNonEmptyString } from '../prototype-safety/non-empty-string.js';
import type { DpoContactMetadata, DsrEndpointMetadata } from './types.js';

/** DSR エンドポイント発見メタデータの well-known パス。 */
const DSR_ENDPOINT_PATH = '/.well-known/dsr-endpoint';

/** DPO 連絡先発見メタデータの well-known パス。 */
const DPO_CONTACT_PATH = '/.well-known/dpo-contact';

/**
 * ドメインを `https://<domain><path>` の取得先 URL に変換する。
 *
 * 入力ドメインはホスト（+任意のポート）のみを受理する。スキーム付き（`https://...`）・パス・
 * クエリ・フラグメントを含む入力は、パス偽装や取得先の取り違えを防ぐため拒否する。生成 URL が
 * HTTPS の origin のみ（パスは well-known 固定）になることを保証する。
 *
 * @param domain Issuer / RP のドメイン（例: `issuer.example.com` / `issuer.example.com:8443`）。
 * @param path 取得する well-known パス。
 * @returns 取得先の HTTPS URL 文字列。
 * @throws ドメイン形式不正（VericertsError、code `10606`）。
 */
function domainToWellKnownUrl(domain: string, path: string): string {
  if (typeof domain !== 'string' || domain.length === 0) {
    throw new VericertsError(ErrorCodes.GDPR_DISCOVERY_INVALID);
  }
  // スキーム・パス区切り・クエリ・フラグメント・空白を含む入力は host 以外を持ち込むため拒否する。
  if (/[/\\?#\s]/.test(domain) || domain.includes('://')) {
    throw new VericertsError(ErrorCodes.GDPR_DISCOVERY_INVALID);
  }
  let url: URL;
  try {
    url = new URL(`https://${domain}${path}`);
  } catch {
    // URL 文字列に入力が含まれ得るため cause を渡さず正規化する。
    throw new VericertsError(ErrorCodes.GDPR_DISCOVERY_INVALID);
  }
  // host 以外（userinfo 等）が混入していないこと、生成パスが well-known 固定であることを検証する。
  if (
    url.protocol !== 'https:' ||
    url.username !== '' ||
    url.password !== '' ||
    url.pathname !== path
  ) {
    throw new VericertsError(ErrorCodes.GDPR_DISCOVERY_INVALID);
  }
  return url.toString();
}

/**
 * well-known URL から発見メタデータの JSON object を取得する。
 *
 * 取得そのもの（タイムアウト・最終 URL の HTTPS 検査・Content-Type 検査・`MAX_DOCUMENT_BYTES`
 * （1 MiB）の本文上限・プロトタイプを外したパース）は横断プリミティブ `http/fetch-json.ts` に
 * 委ねる。本関数は失敗理由を発見用のエラーコードに対応付ける。
 *
 * @param url 取得先の HTTPS URL（`domainToWellKnownUrl` の結果）。
 * @returns プロトタイプを外した JSON object。
 * @throws 取得失敗（code `10605`）・Content-Type / JSON / 非オブジェクト（code `10606`）の場合
 *   （VericertsError）。
 */
async function fetchDiscoveryDocument(url: string): Promise<Record<string, unknown>> {
  const failure = (reason: JsonFetchReason): VericertsError => {
    // 取得は成功して中身が期待と違う失敗だけを「メタデータ不正」に寄せ、残りは取得失敗とする。
    const invalidDocument =
      reason === 'invalid_content_type' ||
      reason === 'invalid_json' ||
      reason === 'invalid_metadata';
    const code = invalidDocument
      ? ErrorCodes.GDPR_DISCOVERY_INVALID
      : ErrorCodes.GDPR_DISCOVERY_FETCH_FAILED;
    // `context` に載せるのは固定の識別子だけ（URL・本文は載せない）。
    return new VericertsError(code, { context: { reason } });
  };
  return (await fetchJsonWithinLimits(url, undefined, failure)) as Record<string, unknown>;
}

/** 非空文字列を取り出す（未定義・型不一致・空文字は `undefined`）。 */
function optionalString(value: unknown): string | undefined {
  return isNonEmptyString(value) ? value : undefined;
}

/**
 * HTTPS の絶対 URL を検証して返す。HTTPS 以外・URL 不正は「スキーマ不正」として拒否する。
 *
 * @param value 検証対象（メタデータ中の URL 文字列）。
 * @returns 正規化した HTTPS URL 文字列。
 * @throws 非文字列・空・非 HTTPS・URL 不正の場合（VericertsError、code `10606`）。
 */
function requireHttpsUrl(value: unknown): string {
  if (typeof value !== 'string' || value.length === 0) {
    throw new VericertsError(ErrorCodes.GDPR_DISCOVERY_INVALID);
  }
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new VericertsError(ErrorCodes.GDPR_DISCOVERY_INVALID);
  }
  if (url.protocol !== 'https:') {
    throw new VericertsError(ErrorCodes.GDPR_DISCOVERY_INVALID);
  }
  return url.toString();
}

/**
 * `/.well-known/dsr-endpoint` を取得・パースする。
 *
 * データ主体の権利 (Art.15–22) 行使のための DSR 受付エンドポイントの参照を発見する。DSR 対応 SLA は
 * Issuer / RP の運用責任範囲であり、SDK は本メタデータの発見のみを提供する。
 *
 * スキーマ検証: `dsrEndpoint`（HTTPS URL、必須）を要求する。`supportedRights` / `formats` は任意だが、
 * 存在する場合は文字列のみの配列であることを要求し、非文字列要素が混在する配列は fail-closed で拒否する
 * （黙って要素を落とすと発見結果を誤認させるため）。
 *
 * @param domain Issuer / RP のドメイン（host + 任意ポート。スキーム / パスは付けない）。
 * @returns DSR エンドポイント発見メタデータ。
 * @throws ドメイン不正 / スキーマ不正（code `10606`）・取得失敗（code `10605`）の場合（VericertsError）。
 */
export async function discoverDsrEndpoint(domain: string): Promise<DsrEndpointMetadata> {
  const url = domainToWellKnownUrl(domain, DSR_ENDPOINT_PATH);
  const doc = await fetchDiscoveryDocument(url);
  const metadata: DsrEndpointMetadata = {
    dsrEndpoint: requireHttpsUrl(doc.dsrEndpoint),
    ...toStringArray('supportedRights', doc.supportedRights),
    ...toStringArray('formats', doc.formats),
  };
  return metadata;
}

/**
 * `/.well-known/dpo-contact` を取得・パースする。
 *
 * Data Protection Officer (Art.37–39) の連絡先メタデータの参照を発見する。SDK 自体は DPO を任命せず、
 * 組込先の Issuer / RP / Wallet Provider が公開する連絡先を発見するのみ。
 *
 * スキーマ検証: `email`（必須・非空文字列）を要求し、`name` / `phone` / `address` / `url`（HTTPS）は
 * 任意。DPO 連絡先の要件（GDPR Art.37(7)）に最低限必要な連絡手段として `email` を必須とする。
 *
 * @param domain Issuer / RP のドメイン（host + 任意ポート。スキーム / パスは付けない）。
 * @returns DPO 連絡先発見メタデータ。
 * @throws ドメイン不正 / スキーマ不正（code `10606`）・取得失敗（code `10605`）の場合（VericertsError）。
 */
export async function discoverDpoContact(domain: string): Promise<DpoContactMetadata> {
  const url = domainToWellKnownUrl(domain, DPO_CONTACT_PATH);
  const doc = await fetchDiscoveryDocument(url);
  const email = optionalString(doc.email);
  if (email === undefined) {
    throw new VericertsError(ErrorCodes.GDPR_DISCOVERY_INVALID);
  }
  const metadata: DpoContactMetadata = {
    email,
    ...pickString('name', doc.name),
    ...pickString('phone', doc.phone),
    ...pickString('address', doc.address),
    ...(doc.url === undefined ? {} : { url: requireHttpsUrl(doc.url) }),
  };
  return metadata;
}

/** 任意の文字列フィールドを spread 可能な部分オブジェクトにする（未設定なら空）。 */
function pickString(key: string, value: unknown): Record<string, string> {
  const str = optionalString(value);
  return str === undefined ? {} : { [key]: str };
}

/**
 * 任意の文字列配列フィールドを spread 可能な部分オブジェクトにする。
 *
 * 未定義なら空を返す。配列だが非文字列要素が混じる場合はスキーマ不正として拒否する（黙って
 * 要素を落とすと発見結果を誤認させるため fail-closed とする）。
 */
function toStringArray(key: string, value: unknown): Record<string, readonly string[]> {
  if (value === undefined) {
    return {};
  }
  if (!Array.isArray(value) || value.some((item) => typeof item !== 'string')) {
    throw new VericertsError(ErrorCodes.GDPR_DISCOVERY_INVALID);
  }
  return { [key]: value as readonly string[] };
}
