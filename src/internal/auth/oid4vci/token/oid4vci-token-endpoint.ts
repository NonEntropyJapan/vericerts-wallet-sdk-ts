/**
 * pre-authorized_code 経路の Token Endpoint の解決（OID4VCI 1.0 §6 / RFC 8414）。
 *
 * OID4VCI 1.0 の Credential Issuer Metadata に `token_endpoint` は無く、Token Endpoint は AS Metadata
 * （RFC 8414）の `token_endpoint` から引く。`receiveCredential` / EUDI `receivePID` /
 * `receiveEAA` / 拡張の `handleReceiveOffer` が同じ解決を通る。
 *
 * AS Metadata に**到達できなかった**（`fetch_failed` / `http_error`）場合に限り、旧 Draft の Issuer Metadata が
 * 宣言する `token_endpoint` へ後方互換でフォールバックする（`source` で観測できる）。**検査起因の拒否**
 * （`non_https_issuer` / `redirect_rejected`（リダイレクトの検査拒否・`opaqueredirect`）/ `insecure_redirect` /
 * `invalid_content_type` / `issuer_mismatch` / `missing_endpoint` 等）は迂回せず再送出する。迂回すると、検査を通っていない宛先へ `pre-authorized_code` / `tx_code` /
 * `client_assertion` が送られる。authorization_code 経路は AS Metadata を必ず引くので `facade/receive.ts` が直接使う。
 */

import { ErrorCodes, VericertsError } from '../../../errors.js';
import type { FetchLike } from '../../../fetch-di.js';
import { isPublicHttpsUrl } from '../../../http/public-https-url.js';
import { ownProperty } from '../../../prototype-safety/own-property.js';
import { resolveAuthorizationServer } from '../identifier/authorization-server.js';
import { fetchAuthorizationServerTokenEndpoint } from '../oid4vci-as-metadata.js';

/** Token Endpoint の解決結果。 */
export interface ResolvedTokenEndpoint {
  /** HTTPS・公開ホストの Token Endpoint。 */
  readonly tokenEndpoint: string;
  /** 由来。`legacy_issuer_metadata` は AS Metadata に到達できず旧 Draft の宣言値へ落ちたことを表す。 */
  readonly source: 'authorization_server' | 'legacy_issuer_metadata';
}

/** Issuer Metadata から Token Endpoint の解決に使う最小の公開契約。 */
export interface PreAuthorizedIssuerEndpoints {
  readonly authorizationServers?: readonly string[];
  readonly tokenEndpoint?: string;
}

/**
 * Token Endpoint を解決する。
 *
 * @param authorizationServer 認可を担う AS の識別子（HTTPS の絶対 URL）。
 * @param legacyTokenEndpoint 旧 Draft の Issuer Metadata が宣言する `token_endpoint`（無ければ `undefined`）。
 * @param fetchImpl HTTP 呼び出しの差し替えシーム。
 * @returns Token Endpoint と由来。
 * @throws AS Metadata が拒否された、または到達できずフォールバック先も無い場合（VericertsError、code `3004`）。
 */
export async function resolveTokenEndpoint(
  authorizationServer: string,
  legacyTokenEndpoint: string | undefined,
  fetchImpl: FetchLike | undefined,
): Promise<ResolvedTokenEndpoint> {
  try {
    const tokenEndpoint = await fetchAuthorizationServerTokenEndpoint(
      authorizationServer,
      fetchImpl,
    );
    return { tokenEndpoint, source: 'authorization_server' };
  } catch (error) {
    const reason = error instanceof VericertsError ? error.context?.reason : undefined;
    // 到達できなかった（`fetch_failed` / `http_error`）場合に限る。検査起因の拒否は再送出する。
    if (
      legacyTokenEndpoint !== undefined &&
      (reason === 'fetch_failed' || reason === 'http_error')
    ) {
      if (!isPublicHttpsUrl(legacyTokenEndpoint)) {
        throw new VericertsError(ErrorCodes.ISSUER_COMMUNICATION_FAILED, {
          context: { reason: 'non_https_endpoint' },
        });
      }
      return { tokenEndpoint: legacyTokenEndpoint, source: 'legacy_issuer_metadata' };
    }
    throw error;
  }
}

/**
 * `pre-authorized_code` grant の Token Endpoint を解決する（各受領経路が共有する唯一の入口）。
 * AS は {@link resolveAuthorizationServer}、解決は {@link resolveTokenEndpoint}。
 *
 * @param grant Offer の `pre-authorized_code` grant。
 * @param issuer Issuer Metadata（`authorizationServers` / 旧 `tokenEndpoint` だけを読む）。
 * @param credentialIssuer Offer の `credential_issuer`。
 * @param fetchImpl HTTP 呼び出しの差し替えシーム。
 */
export async function resolvePreAuthorizedTokenEndpoint(
  grant: object,
  issuer: PreAuthorizedIssuerEndpoints,
  credentialIssuer: string,
  fetchImpl: FetchLike | undefined,
): Promise<ResolvedTokenEndpoint> {
  return resolveTokenEndpoint(
    resolveAuthorizationServer(
      grant,
      ownProperty<readonly string[]>(issuer, 'authorizationServers'),
      credentialIssuer,
    ),
    ownProperty<string>(issuer, 'tokenEndpoint'),
    fetchImpl,
  );
}
