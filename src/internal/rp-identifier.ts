/**
 * RP（Relying Party）識別子の正規化（横断ヘルパー）。
 *
 * Pseudonym 鍵の HKDF salt と、破棄済み RP の記録には同じ正規形を使う。
 */

import { ErrorCodes, VericertsError } from './errors.js';

/** 先頭が `scheme://` で始まる（= 文字列全体が scheme 付き URL の）識別子を判定する。 */
const SCHEME_URL_PATTERN = /^[a-z][a-z0-9+.-]*:\/\//i;

/** OpenID4VP prefixed `client_id` の prefix（`origin` / `redirect_uri` / `x509_san_dns` 等）。 */
const CLIENT_ID_PREFIX_PATTERN = /^[a-z0-9_-]+$/i;

/** scheme 付き URL を `scheme://host[:port]`（scheme・host 小文字）の origin へ正規化する。 */
function canonicalizeUrlOrigin(value: string): string {
  if (!SCHEME_URL_PATTERN.test(value)) {
    throw new VericertsError(ErrorCodes.RP_IDENTIFIER_INVALID);
  }
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new VericertsError(ErrorCodes.RP_IDENTIFIER_INVALID);
  }
  // URL.host は既に小文字化されるが、明示的に lower にして決定性を担保する。
  return `${url.protocol.toLowerCase()}//${url.host.toLowerCase()}`;
}

/**
 * RP 識別子を正規化する。
 *
 * 前後の空白を除去し、決定的な正規形へ写像して RP のサブドメイン偽装や大文字小文字揺れによる別
 * Pseudonym 生成を防ぐ。形式ごとの正規形は次のとおり（いずれも RP ごとに一意で、異なる RP が同じ
 * 正規形へ潰れない）。
 *
 * - `scheme://…` で始まる URL: origin（`scheme://host[:port]`、scheme・host 小文字、path / query は落とす）。
 * - `<prefix>:<scheme>://…` の prefixed `client_id`（`origin:https://rp.example`・
 *   `redirect_uri:https://rp.example/cb` 等）: prefix（小文字）を保ったまま URL 部のみ origin 化した
 *   `prefix:origin`（`new URL` に全体を渡すと `origin:` が scheme と解釈され host が空になり、
 *   すべての `origin:` RP が `origin://` に潰れていた）。
 * - それ以外（FQDN / `x509_san_dns:…` 等）: 全体を小文字化した文字列。
 *
 * @param rpIdentifier RP のクライアント識別子（FQDN / URL / prefixed client_id）。
 * @returns 正規化した RP 識別子。
 * @throws 空・非文字列・不正形式の場合（VericertsError、code `10201`）。
 */
export function canonicalizeRpIdentifier(rpIdentifier: string): string {
  if (typeof rpIdentifier !== 'string') {
    throw new VericertsError(ErrorCodes.RP_IDENTIFIER_INVALID);
  }
  const trimmed = rpIdentifier.trim();
  if (trimmed.length === 0) {
    throw new VericertsError(ErrorCodes.RP_IDENTIFIER_INVALID);
  }
  if (SCHEME_URL_PATTERN.test(trimmed)) {
    return canonicalizeUrlOrigin(trimmed);
  }
  if (trimmed.includes('://')) {
    // `<prefix>:<URL>` 形式。prefix と URL 部を分け、URL 部のみ origin 化する。
    const separator = trimmed.indexOf(':');
    const prefix = trimmed.slice(0, separator);
    if (!CLIENT_ID_PREFIX_PATTERN.test(prefix)) {
      throw new VericertsError(ErrorCodes.RP_IDENTIFIER_INVALID);
    }
    return `${prefix.toLowerCase()}:${canonicalizeUrlOrigin(trimmed.slice(separator + 1))}`;
  }
  return trimmed.toLowerCase();
}
